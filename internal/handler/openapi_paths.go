package handler

import (
	_ "embed"
	"encoding/json"
)

// openapiPathsJSON 存放 OpenAPI paths 段的完整定义，已外置为 openapi_paths.json
// 并经 //go:embed 编译期嵌入，运行时零网络/零 IO 直接反序列化装配。
//
// 外置动机：原 buildOpenAPIPaths 为 5200+ 行的巨型 map 字面量（god file），
// 拖慢编辑器与编译期解析；外置后源码与数据分离，且数据可被 Python/工具复用。
//
// 4 处 "/...*/finalization" 在原始代码中引用运行时 finalizationRequestSchema 参数，
// 无法静态写死，故以哨兵字符串 "__FINALIZATION_REQUEST_SCHEMA__" 占位，
// 运行时由 replaceFinalization 递归替换为真实 schema（见 openapi_snapshot_test.go 回归守护）。
//
//go:embed openapi_paths.json
var openapiPathsJSON []byte

// finalizationSentinel 是 openapi_paths.json 中占位运行时 schema 的哨兵标记。
const finalizationSentinel = "__FINALIZATION_REQUEST_SCHEMA__"

// buildOpenAPIPaths 构造 OpenAPI spec 的 paths 段。
// 自 openapi_paths.json（//go:embed）反序列化，并将 4 处哨兵递归替换为运行时
// finalizationRequestSchema，行为与原 5200+ 行字面量版本逐字节一致。
func buildOpenAPIPaths(finalizationRequestSchema map[string]interface{}) map[string]interface{} {
	var paths map[string]interface{}
	if err := json.Unmarshal(openapiPathsJSON, &paths); err != nil {
		// 嵌入资源在编译期已校验，运行时解析失败属不可恢复错误。
		panic("openapi_paths.json 解析失败: " + err.Error())
	}
	replaceFinalization(paths, finalizationRequestSchema)
	return paths
}

// replaceFinalization 递归遍历 paths，将所有等于 finalizationSentinel 的字符串
// 替换为运行时传入的 finalizationRequestSchema，恢复动态装配语义。
func replaceFinalization(v interface{}, schema map[string]interface{}) {
	switch node := v.(type) {
	case map[string]interface{}:
		for k, val := range node {
			if s, ok := val.(string); ok && s == finalizationSentinel {
				node[k] = schema
				continue
			}
			replaceFinalization(val, schema)
		}
	case []interface{}:
		for _, item := range node {
			replaceFinalization(item, schema)
		}
	}
}
