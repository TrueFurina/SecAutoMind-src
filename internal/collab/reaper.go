package collab

import (
	"time"

	"go.uber.org/zap"
)

// ReapOnce 扫描一次已过墙钟硬限的进行中任务，把它们退回池。
//
// 判定完全交给 DB 的单条条件式 UPDATE（status=claimed AND wall_clock_deadline <= now），
// 因此天然并发安全，也天然「不阻塞其它任务」：它只碰超时的那几行。
//
// 测试可直接调用本方法并注入伪时钟，无需真等墙钟——reaper 循环只是它的定时外壳。
func (s *Service) ReapOnce() (int64, error) {
	now := s.now()
	n, err := s.db.ReturnStaleCollabTasks(now)
	if err != nil {
		return 0, err
	}
	if n > 0 {
		s.auditEvent(Actor{}, ActionTaskReap, "success", "卡死回收：超时任务已自动退回池",
			"collab_task", "", map[string]interface{}{"returned": n, "at": now.Format(time.RFC3339)})
		if s.logger != nil {
			s.logger.Info("协同任务卡死回收", zap.Int64("returned", n))
		}
	}
	return n, nil
}

// StartReaper 启动后台回收循环。重复调用是幂等的（第二次直接返回）。
func (s *Service) StartReaper() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.doneCh = make(chan struct{})
	stop := s.stopCh
	done := s.doneCh
	s.mu.Unlock()

	go func() {
		defer close(done)
		ticker := time.NewTicker(s.reaperInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if _, err := s.ReapOnce(); err != nil {
					s.warn("协同任务卡死回收失败", zap.Error(err))
				}
			}
		}
	}()
}

// StopReaper 停止后台回收循环并等待 goroutine 退出。未启动时是空操作。
func (s *Service) StopReaper() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	stop := s.stopCh
	done := s.doneCh
	s.stopCh = nil
	s.doneCh = nil
	s.mu.Unlock()

	close(stop)
	<-done
}

// ReaperRunning 报告回收循环是否在跑（供 /health 或演示总览展示）。
func (s *Service) ReaperRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}
