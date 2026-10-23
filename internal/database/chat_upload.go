package database

import (
	"strings"
	"time"
)

// ChatUploadArtifact 对话产物条目。sha256/size/kind 为空或 0 表示历史数据未登记。
type ChatUploadArtifact struct {
	RelativePath string    `json:"relative_path"`
	SHA256       string    `json:"sha256"`
	Size         int64     `json:"size"`
	Kind         string    `json:"kind"`
	CreatedAt    time.Time `json:"created_at"`
}

func (db *DB) UpsertChatUploadArtifact(relativePath, conversationID, ownerUserID, sha256, kind string, size int64) error {
	relativePath = strings.TrimSpace(relativePath)
	conversationID = strings.TrimSpace(conversationID)
	ownerUserID = strings.TrimSpace(ownerUserID)
	if relativePath == "" || conversationID == "" || ownerUserID == "" {
		return nil
	}
	_, err := db.Exec(`
		INSERT INTO chat_upload_artifacts(relative_path, conversation_id, owner_user_id, created_at, sha256, size, kind)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(relative_path) DO UPDATE SET
			conversation_id=excluded.conversation_id,
			owner_user_id=excluded.owner_user_id,
			sha256=excluded.sha256,
			size=excluded.size,
			kind=excluded.kind
	`, relativePath, conversationID, ownerUserID, time.Now(), sha256, size, kind)
	return err
}

// ListChatUploadArtifacts 按对话列出产物（仅限归属人），用于产物索引面板。
func (db *DB) ListChatUploadArtifacts(conversationID, ownerUserID string) ([]ChatUploadArtifact, error) {
	rows, err := db.Query(`
		SELECT relative_path, sha256, size, kind, created_at
		FROM chat_upload_artifacts
		WHERE conversation_id = ? AND owner_user_id = ?
		ORDER BY created_at DESC, relative_path ASC
	`, strings.TrimSpace(conversationID), strings.TrimSpace(ownerUserID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ChatUploadArtifact, 0, 8)
	for rows.Next() {
		var a ChatUploadArtifact
		if err := rows.Scan(&a.RelativePath, &a.SHA256, &a.Size, &a.Kind, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (db *DB) GetChatUploadArtifact(relativePath string) (conversationID, ownerUserID string, ok bool) {
	err := db.QueryRow(`SELECT conversation_id, owner_user_id FROM chat_upload_artifacts WHERE relative_path = ?`, strings.TrimSpace(relativePath)).Scan(&conversationID, &ownerUserID)
	return conversationID, ownerUserID, err == nil
}

// InvalidateChatUploadArtifactHash 在文件内容变更后清空哈希，保留归属关系。
// 只更新已登记行；未登记文件（如 workspace 源）不会被强行插入。
// 语义：行存在但 sha256 为空 = "登记过、内容已变更、未重新登记"，与"从未登记"区分。
func (db *DB) InvalidateChatUploadArtifactHash(relativePath string, size int64) error {
	relativePath = strings.Trim(strings.TrimSpace(relativePath), "/")
	if relativePath == "" {
		return nil
	}
	_, err := db.Exec(`UPDATE chat_upload_artifacts SET sha256 = '', size = ? WHERE relative_path = ?`, size, relativePath)
	return err
}

// GetChatUploadArtifactMeta 读取产物的完整性登记值；ok=false 表示未登记。
func (db *DB) GetChatUploadArtifactMeta(relativePath string) (sha256 string, size int64, kind string, ok bool) {
	err := db.QueryRow(`SELECT sha256, size, kind FROM chat_upload_artifacts WHERE relative_path = ?`,
		strings.TrimSpace(relativePath)).Scan(&sha256, &size, &kind)
	return sha256, size, kind, err == nil
}

func (db *DB) DeleteChatUploadArtifactPath(relativePath string) error {
	path := strings.Trim(strings.TrimSpace(relativePath), "/")
	if path == "" {
		return nil
	}
	_, err := db.Exec(`DELETE FROM chat_upload_artifacts WHERE relative_path = ? OR relative_path LIKE ? ESCAPE '\'`, path, escapeLikePrefix(path)+"/%")
	return err
}

func (db *DB) RenameChatUploadArtifactPath(oldPath, newPath string) error {
	oldPath = strings.Trim(strings.TrimSpace(oldPath), "/")
	newPath = strings.Trim(strings.TrimSpace(newPath), "/")
	if oldPath == "" || newPath == "" {
		return nil
	}
	_, err := db.Exec(`
		UPDATE chat_upload_artifacts
		SET relative_path = CASE
			WHEN relative_path = ? THEN ?
			ELSE ? || substr(relative_path, length(?) + 1)
		END
		WHERE relative_path = ? OR relative_path LIKE ? ESCAPE '\'
	`, oldPath, newPath, newPath, oldPath, oldPath, escapeLikePrefix(oldPath)+"/%")
	return err
}

func escapeLikePrefix(value string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value)
}
