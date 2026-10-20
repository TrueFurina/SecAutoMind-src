package app

import (
	"embed"
	"io/fs"
)

// 嵌入前端资源（模板 + 静态），使 exe 在任意目录双击即用，不依赖磁盘上的
// web/ 目录（单文件分发）。
//
// 注意：说明文字不要写成 "// go:embed ..."——`//` 与 `go:embed` 之间多一个空格
// 就不再是编译指令，staticcheck SA9009 会报"ineffectual compiler directive"。
// 真正的指令在紧随其后的两行。
//
//go:embed web/templates/*.html
//go:embed web/static/css/* web/static/js/* web/static/i18n/* web/static/vendor/* web/static/favicon.ico web/static/logo.png
var webFS embed.FS

// webTemplatesSub 返回模板子 FS（html/template.ParseFS 用）

// webTemplatesSub 返回模板子 FS（html/template.ParseFS 用）
func webTemplatesSub() fs.FS {
	sub, err := fs.Sub(webFS, "web/templates")
	if err != nil {
		return webFS
	}
	return sub
}

// webStaticSub 返回静态资源子 FS（gin StaticFS 用）

// webStaticSub 返回静态资源子 FS（gin StaticFS 用）
func webStaticSub() fs.FS {
	sub, err := fs.Sub(webFS, "web/static")
	if err != nil {
		return webFS
	}
	return sub
}

// App 应用
