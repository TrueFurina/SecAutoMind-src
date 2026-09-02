package logger

import (
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	*zap.Logger
}

func New(level, output string) *Logger {
	var zapLevel zapcore.Level
	switch level {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.InfoLevel
	}

	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zapLevel)
	config.EncoderConfig.TimeKey = "timestamp"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	var writeSyncer zapcore.WriteSyncer
	if output == "" || output == "stdout" {
		// GUI（windowsgui）模式下无控制台，stdout 日志不可见——
		// 兜底写入 logs/secautomind.log，保证日志可查。
		if err := os.MkdirAll("logs", 0755); err == nil {
			file, fErr := os.OpenFile("logs/secautomind.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			if fErr == nil {
				writeSyncer = zapcore.AddSync(file)
			} else {
				writeSyncer = zapcore.AddSync(os.Stdout)
			}
		} else {
			writeSyncer = zapcore.AddSync(os.Stdout)
		}
	} else {
		// 输出到文件：确保父目录存在（如 logs/secautomind.log）
		if dir := filepath.Dir(output); dir != "." && dir != "" {
			_ = os.MkdirAll(dir, 0755)
		}
		file, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			writeSyncer = zapcore.AddSync(os.Stdout)
		} else {
			writeSyncer = zapcore.AddSync(file)
		}
	}

	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(config.EncoderConfig),
		writeSyncer,
		zapLevel,
	)

	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))

	return &Logger{Logger: logger}
}

func (l *Logger) Fatal(msg string, fields ...interface{}) {
	zapFields := make([]zap.Field, 0, len(fields))
	for _, f := range fields {
		switch v := f.(type) {
		case error:
			zapFields = append(zapFields, zap.Error(v))
		default:
			zapFields = append(zapFields, zap.Any("field", v))
		}
	}
	l.Logger.Fatal(msg, zapFields...)
}
