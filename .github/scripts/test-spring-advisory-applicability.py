import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "applicability", Path(__file__).with_name("check-spring-advisory-applicability.py")
)
applicability = importlib.util.module_from_spec(spec)
spec.loader.exec_module(applicability)


class ApplicabilityTest(unittest.TestCase):
    def test_rest_api_control(self):
        self.assertTrue(applicability.check_source(
            '@RestController class Api { @GetMapping("/api/items") '
            'ResponseEntity<Item> get() { return ResponseEntity.ok(item); } }'
        ))

    def test_vulnerable_feature_forms_require_review(self):
        for source in [
            "new XsltView()", "import org.springframework.web.servlet.view.*;",
            'Class.forName("org.springframework.web.servlet.view.xslt.XsltView")',
            "@Controller class WildcardViews {}", "new ModelAndView(name)",
            "registry.addViewController(path)", "new SseEmitter()",
            "FragmentsRendering.fragment(name)", "ServerSentEvent.builder(data)",
            'produces = "text/event-stream"', "MediaType.TEXT_EVENT_STREAM_VALUE",
            '<bean class="org.springframework.web.servlet.view.xslt.XsltView"/>',
        ]:
            with self.subTest(source=source):
                self.assertFalse(applicability.check_source(source))


if __name__ == "__main__":
    unittest.main()
