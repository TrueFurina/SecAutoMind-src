"""xuanhun_signin（JPEG 尾部嵌 PNG + 视觉 flag）OCR 回归测试。

锁定 M3 增强：presolve 经 jpeg_png_embedded skill 提取内嵌 PNG 后用 tesseract OCR
命中视觉 flag，使真题集确定性覆盖从 14/15 提升至 15/15。CI 环境若无 tesseract 则 skip，
避免在没有 OCR 引擎的机器上误红。
"""
from __future__ import annotations
import os
import sys
import unittest

# 让仓库根可被 import（与项目其它测试一致）
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from skills.jpeg_png_embedded import _locate_tesseract, run  # noqa: E402

_ATTACH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "questions_real", "_attachments", "misc",
    "real_misc_xuanhun_signin", "xz1.jpg",
)


class TestJpegPngOcr(unittest.TestCase):
    def test_tesseract_locatable(self):
        """tesseract 可定位性：**声明了才要求能用**，没声明就明确 skip。

        2026-11-08 服务器实证：这台机器上 tesseract 不存在，原写法
        `assertIsNotNone(exe, "tesseract 未在 PATH…")` 直接把门禁打成红。
        但 tesseract 是**系统级包**（`pyproject` 的 `vision` extra 里 pytesseract
        只是壳，tesseract 本体要 apt/conda 装），`requires-python` 装不出它 ——
        于是「干净机器必红」，和 babysthird 那条是同一族假红：在作者机器绿、
        在别人机器红。改成按声明判定：

          ① `vision` extra 没装（pytesseract 不可导入）→ 该能力本身就没被声明，
             skip 并写明原因（不是"通过"）
          ② `vision` 装了但 tesseract 找不到 → 配置错误，**红**（声明了就必须能用）
        """
        exe, tdata = _locate_tesseract()
        if exe is None:
            try:
                import pytesseract  # noqa: F401
            except Exception:
                self.skipTest(
                    "vision 可选依赖未安装（pyproject `vision` extra）—— "
                    "tesseract 本体属系统包，pip 装不来；OCR 能力未声明，故不作判定")
            self.fail("vision extra 已安装但找不到 tesseract：声明了就必须能用（配置错误）")
        self.assertIsNotNone(tdata, "tessdata 目录（含 eng.traineddata）未定位")

    @unittest.skipUnless(os.path.isfile(_ATTACH), "xz1.jpg 附件缺失")
    def test_xuanhun_signin_ocr_flag(self):
        exe, _ = _locate_tesseract()
        if not exe:
            self.skipTest("tesseract 不可用，跳过 OCR 断言")
        r = run({"path": _ATTACH})
        self.assertTrue(r.get("ok"), f"skill 执行失败: {r}")
        self.assertEqual(r.get("flag"), "flag{mooaudqxs5nbydw3}",
                         "xuanhun_signin 视觉 flag 未被 OCR 命中")
        self.assertEqual(r.get("flag_source"), "ocr:tesseract")


if __name__ == "__main__":
    unittest.main()
