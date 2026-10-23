const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const SETTINGS = path.join(__dirname, 'settings.js');
const source = fs.readFileSync(SETTINGS, 'utf8');

// 提取 buildToolMetaBadges 及其依赖：settingsEscapeAttr + TOOL_TRUST_META。
// settingsEscapeAttr 调用全局 escapeHtml（auth.js 定义，依赖 DOM），
// 这里用等价的 DOM 实现替身——测的是徽章 HTML 结构，不是浏览器转义行为。
function extract(startMarker, endMarker) {
    const start = source.indexOf(startMarker);
    const end = source.indexOf(endMarker, start);
    assert.notEqual(start, -1, `${startMarker} 应存在`);
    assert.notEqual(end, -1, `${endMarker} 应出现在 ${startMarker} 之后`);
    return source.slice(start, end);
}

const stubs = `
function escapeHtml(text) {
    return String(text == null ? '' : text)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
`;

const factory = new Function(
    `${stubs}\n${extract('function settingsEscapeAttr', 'function settingsEscapeJsStringAttr')}\n` +
    `${extract('const TOOL_TRUST_META', 'function renderToolsList')}\n` +
    `return { buildToolMetaBadges, TOOL_TRUST_META };`
);
const { buildToolMetaBadges, TOOL_TRUST_META } = factory();

test('自研工具只渲染来源与信任级，不出许可证与上游链接', () => {
    const html = buildToolMetaBadges({ name: 'exec', source: 'self', trust: 'builtin' });
    assert.match(html, /class="external-tool-badge"[^>]*>自研</);
    assert.match(html, /class="external-tool-badge"[^>]*>内置</);
    assert.doesNotMatch(html, /lic-badge|lic-unverified|upstream-link/);
});

test('外部 MCP 工具（无元数据字段）不渲染任何徽章', () => {
    assert.equal(buildToolMetaBadges({ name: 'burp-ext', is_external: true }), '');
    assert.equal(buildToolMetaBadges({}), '');
    assert.equal(buildToolMetaBadges(null), '');
    assert.equal(buildToolMetaBadges(undefined), '');
});

test('已核实许可证渲染绿色徽章，上游渲染为可点击链接', () => {
    const html = buildToolMetaBadges({
        name: 'ffuf', source: 'upstream', trust: 'builtin',
        license: 'MIT', upstream: 'https://github.com/ffuf/ffuf'
    });
    assert.match(html, /class="external-tool-badge lic-badge"[^>]*title="已核实许可证：MIT"[^>]*>MIT</);
    assert.doesNotMatch(html, /lic-unverified/);
    // 链接必须是新窗口 + noopener，且带完整 URL
    assert.match(html, /<a class="external-tool-badge upstream-link" href="https:\/\/github\.com\/ffuf\/ffuf" target="_blank" rel="noopener noreferrer"/);
    // 点击徽章应阻止冒泡，避免误触发展开详情
    assert.match(html, /onclick="event\.stopPropagation\(\)"/);
});

test('未核实许可证渲染灰色"未核实"徽章且不出上游链接', () => {
    for (const bad of ['unknown', '', undefined, null]) {
        const html = buildToolMetaBadges({
            name: 'dnsenum', source: 'upstream', trust: 'builtin',
            license: bad, upstream: ''
        });
        assert.match(html, /class="external-tool-badge lic-unverified"[^>]*>许可证未核实</,
            `license=${JSON.stringify(bad)} 应渲染未核实徽章`);
        assert.doesNotMatch(html, /lic-badge"/, `license=${JSON.stringify(bad)} 不应渲染已核实徽章`);
        assert.doesNotMatch(html, /upstream-link/, '无 upstream 时不应渲染链接');
    }
});

test('长自定义许可证标签截断、title 保留全文', () => {
    const html = buildToolMetaBadges({
        name: 'nmap', source: 'upstream', trust: 'builtin',
        license: 'Nmap Public Source License', upstream: 'https://github.com/nmap/nmap'
    });
    assert.match(html, /title="已核实许可证：Nmap Public Source License"/);
    assert.match(html, />Nmap Public Sou…</);   // 截断为 15 字符 + 省略号
    assert.doesNotMatch(html, />Nmap Public Source License</); // 标签本身不再撑爆
});

test('许可证名中的 HTML 被转义，不构成注入', () => {
    const html = buildToolMetaBadges({
        name: 'x', source: 'upstream', trust: 'builtin',
        license: '"><img src=x onerror=alert(1)>', upstream: 'https://e.x'
    });
    assert.doesNotMatch(html, /<img src=x/);
    assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
    // title 与标签都进了属性上下文，引号也要被转义
    assert.doesNotMatch(html, /title="[^"]*""><img/);
});

test('信任级标签取自统一的信任级元数据表', () => {
    for (const key of Object.keys(TOOL_TRUST_META)) {
        const html = buildToolMetaBadges({ source: 'upstream', trust: key });
        assert.match(html, new RegExp(`>${TOOL_TRUST_META[key].label}</`), `trust=${key}`);
    }
    // 未知信任级不渲染，而不是渲染成 undefined
    assert.doesNotMatch(buildToolMetaBadges({ source: 'upstream', trust: 'bogus' }), />undefined</);
});

test('source 为上游但未登记 upstream 时，来源徽章提示未登记', () => {
    const html = buildToolMetaBadges({ name: 'gdb', source: 'upstream', trust: 'builtin', license: 'unknown' });
    assert.match(html, />上游</);
    assert.match(html, /title="封装外部 CLI 工具（上游地址未登记）"/);
    assert.match(html, /lic-unverified/);
});
