from pathlib import Path
import re
import unittest


WRAPPER_SOURCE = (
    Path(__file__).parents[2]
    / "lib"
    / "inputleap"
    / "PlatformScreenLoggingWrapper.cpp"
)


class PlatformScreenLoggingWrapperPolicyTests(unittest.TestCase):
    def test_leave_delegates_to_wrapped_screen_exactly_once(self):
        source = WRAPPER_SOURCE.read_text(encoding="utf-8")
        match = re.search(
            r"void\s+PlatformScreenLoggingWrapper::leave\(\)\s*\{(?P<body>.*?)\}",
            source,
            re.DOTALL,
        )

        self.assertIsNotNone(match, "PlatformScreenLoggingWrapper::leave() is missing")
        self.assertEqual(match.group("body").count("screen_->leave();"), 1)


if __name__ == "__main__":
    unittest.main()
