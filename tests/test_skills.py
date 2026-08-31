from pathlib import Path
import asyncio
import unittest

from langchain_core.messages import HumanMessage, SystemMessage

from middleware import skill_middleware
from tools import load_skill, load_skills


class SkillLoadingTests(unittest.TestCase):
    def test_all_security_skills_load(self) -> None:
        expected = {
            "semgrep-security",
            "semgrep-rule-authoring",
            "security-review",
            "threat-model-generation",
            "secrets-gitleaks",
            "dependency-scanning",
            "security-agent-upgrade",
        }
        skills = load_skills()
        self.assertEqual(expected, set(skills))
        self.assertTrue(all(Path(skill["path"]).is_file() for skill in skills.values()))

    def test_explicit_and_automatic_selection(self) -> None:
        explicit = skill_middleware.select_skills({"skill_name": "threat-model-generation"})
        automatic = skill_middleware.select_skills(
            {"messages": [HumanMessage(content="Gitleaks와 의존성 CVE를 검사해줘")]}
        )
        self.assertEqual(["threat-model-generation"], explicit)
        self.assertEqual(["secrets-gitleaks", "dependency-scanning"], automatic)

    def test_project_upgrade_skill_selection(self) -> None:
        selected = skill_middleware.select_skills(
            {"messages": [HumanMessage(content="이 LangGraph 에이전트를 고도화해줘")]}
        )
        self.assertEqual(["security-agent-upgrade"], selected)

    def test_tool_lists_and_loads_skills(self) -> None:
        listing = load_skill.invoke({"skill_name": ""})
        instructions = load_skill.invoke({"skill_name": "security-review"})
        self.assertIn("semgrep-security", listing)
        self.assertIn("High-Confidence Security Review", instructions)

    def test_middleware_injects_only_selected_skill(self) -> None:
        class Request:
            def __init__(self) -> None:
                self.state = {"skill_name": "secrets-gitleaks"}
                self.system_message = SystemMessage(content="base prompt")

            def override(self, **values):
                self.system_message = values["system_message"]
                return self

        captured = {}

        def handler(request):
            captured["prompt"] = request.system_message.content
            return "ok"

        result = skill_middleware.wrap_model_call(Request(), handler)
        self.assertEqual("ok", result.model_response)
        self.assertEqual({"active_skills": ["secrets-gitleaks"]}, result.command.update)
        self.assertIn("Secrets Detection with Gitleaks", captured["prompt"])
        self.assertNotIn("STRIDE Threat Model Generation", captured["prompt"])

    def test_async_middleware_injects_selected_skill(self) -> None:
        class Request:
            def __init__(self) -> None:
                self.state = {"skill_name": "secrets-gitleaks"}
                self.system_message = SystemMessage(content="base prompt")

            def override(self, **values):
                self.system_message = values["system_message"]
                return self

        captured = {}

        async def handler(request):
            captured["prompt"] = request.system_message.content
            return "ok"

        result = asyncio.run(skill_middleware.awrap_model_call(Request(), handler))
        self.assertEqual("ok", result.model_response)
        self.assertEqual({"active_skills": ["secrets-gitleaks"]}, result.command.update)
        self.assertIn("Secrets Detection with Gitleaks", captured["prompt"])

    def test_async_middleware_passthrough_without_skill(self) -> None:
        class Request:
            def __init__(self) -> None:
                self.state = {}
                self.system_message = SystemMessage(content="base prompt")

            def override(self, **values):  # pragma: no cover - should not be called
                raise AssertionError("override should not run when no skill selected")

        async def handler(request):
            return request.system_message.content

        result = asyncio.run(skill_middleware.awrap_model_call(Request(), handler))
        self.assertEqual("base prompt", result)


if __name__ == "__main__":
    unittest.main()
