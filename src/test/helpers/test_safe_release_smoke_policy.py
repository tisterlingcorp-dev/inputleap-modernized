from __future__ import annotations

import ast
import json
from pathlib import Path
import tempfile
import unittest


SMOKE_SCRIPT = Path(__file__).with_name("safe-release-smoke.py")


def load_function(name: str):
    tree = ast.parse(SMOKE_SCRIPT.read_text(encoding="utf-8"), filename=str(SMOKE_SCRIPT))
    definitions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    if not definitions:
        raise AssertionError(f"safe smoke is missing {name}()")
    namespace: dict = {}
    exec(compile(ast.Module(body=definitions, type_ignores=[]), str(SMOKE_SCRIPT), "exec"), namespace)
    return namespace[name]


def ast_identifiers(node) -> set[str]:
    identifiers = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            identifiers.add(child.id)
        elif isinstance(child, ast.Attribute):
            identifiers.add(child.attr)
        elif isinstance(child, ast.Constant) and isinstance(child.value, str):
            identifiers.add(child.value)
    return identifiers


def subscript_constant_value(node):
    slice_node = node.slice
    if isinstance(slice_node, ast.Index):
        slice_node = slice_node.value
    return slice_node.value if isinstance(slice_node, ast.Constant) else None


class SafeReleaseSmokePolicyTests(unittest.TestCase):
    def test_policy_uses_only_python38_ast_apis(self):
        policy_tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        unsupported_calls = [
            node
            for node in ast.walk(policy_tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "ast"
            and node.func.attr == "unparse"
        ]

        self.assertEqual(unsupported_calls, [])

    def test_registry_enumeration_only_accepts_no_more_items_as_completion(self):
        enumerate_items = load_function("enumerate_registry_items")
        values = iter(["first", "second"])

        def complete_normally(_index):
            try:
                return next(values)
            except StopIteration:
                error = OSError("done")
                error.winerror = 259
                raise error

        self.assertEqual(enumerate_items(complete_normally), ["first", "second"])

        def fail_with_unknown_state(_index):
            error = OSError("access denied")
            error.winerror = 5
            raise error

        with self.assertRaises(OSError):
            enumerate_items(fail_with_unknown_state)

    def test_smoke_has_no_persisted_state_mutation_helper(self):
        self.assertFalse(
            SMOKE_SCRIPT.with_name("safe_release_smoke_state.py").exists(),
            "obsolete destructive persisted-state helper must not ship with the smoke",
        )

    def test_cleanup_steps_continue_after_an_independent_failure(self):
        run_steps = load_function("run_cleanup_steps")
        completed = []

        def fail():
            raise RuntimeError("first failed")

        errors = run_steps([("first", fail), ("second", lambda: completed.append("second"))])

        self.assertEqual(completed, ["second"])
        self.assertEqual(errors[0]["step"], "first")
        self.assertEqual(errors[0]["error_type"], "RuntimeError")

    def test_late_error_dialog_is_rejected_from_fresh_top_window_snapshot(self):
        evaluate = load_function("evaluate_top_windows")
        windows = [
            {"title": "InputLeap", "visible": True},
            {"title": "Falha ao iniciar serviço", "visible": True},
        ]

        result = evaluate(windows)

        self.assertFalse(result["pass"])
        self.assertEqual(result["error_windows"], [windows[1]])

        body_only_error = {
            "title": "Aviso",
            "visible": True,
            "uia_texts": ["Falha ao iniciar o serviço"],
        }
        result = evaluate([windows[0], body_only_error])
        self.assertFalse(result["pass"])
        self.assertEqual(result["error_windows"], [body_only_error])

    def test_any_visible_modal_or_disabled_main_window_is_rejected(self):
        evaluate = load_function("evaluate_top_windows")
        main = {
            "title": "InputLeap",
            "visible": True,
            "enabled": False,
            "uia_texts": ["Pronto", "Pronto para conectar"],
        }
        warning = {
            "title": "Aviso",
            "visible": True,
            "enabled": True,
            "uia_texts": ["Confirme a configuração"],
        }

        result = evaluate([main, warning])

        self.assertFalse(result["pass"])
        self.assertFalse(result["main_window_enabled"])
        self.assertEqual(result["unexpected_visible_windows"], [warning])

    def test_output_preflight_failures_are_sanitized_before_optional_imports(self):
        tree = ast.parse(
            SMOKE_SCRIPT.read_text(encoding="utf-8"), filename=str(SMOKE_SCRIPT)
        )
        preflight_tries = [
            node
            for node in tree.body
            if isinstance(node, ast.Try)
            and {
                call.func.id
                for call in ast.walk(node)
                if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
            }.issuperset({"invalidate_previous_result"})
            and any(
                isinstance(call.func, ast.Attribute) and call.func.attr == "mkdir"
                for call in ast.walk(node)
                if isinstance(call, ast.Call)
            )
        ]

        self.assertEqual(len(preflight_tries), 1)
        preflight = preflight_tries[0]
        self.assertTrue(any(
            isinstance(call.func, ast.Name)
            and call.func.id == "emit_sanitized_failure"
            for handler in preflight.handlers
            for call in ast.walk(handler)
            if isinstance(call, ast.Call)
        ))
        self.assertTrue(any(
            isinstance(node, ast.Raise)
            and isinstance(node.exc, ast.Call)
            and isinstance(node.exc.func, ast.Name)
            and node.exc.func.id == "SystemExit"
            for handler in preflight.handlers
            for node in ast.walk(handler)
        ))

    def test_cleanup_finalization_is_sanitized_and_fail_closed(self):
        tree = ast.parse(
            SMOKE_SCRIPT.read_text(encoding="utf-8"), filename=str(SMOKE_SCRIPT)
        )
        smoke_try = next(
            node
            for node in tree.body
            if isinstance(node, ast.Try)
            and any(
                isinstance(call.func, ast.Attribute) and call.func.attr == "Popen"
                for call in ast.walk(node)
                if isinstance(call, ast.Call)
            )
        )
        guarded_finalizers = [
            node for node in smoke_try.finalbody if isinstance(node, ast.Try)
        ]

        self.assertEqual(len(guarded_finalizers), 1)
        finalizer = guarded_finalizers[0]
        guarded_calls = {
            call.func.attr
            for statement in finalizer.body
            for call in ast.walk(statement)
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
        }
        self.assertIn("poll", guarded_calls)
        self.assertIn("write_text", guarded_calls)
        handler_identifiers = {
            identifier
            for handler in finalizer.handlers
            for identifier in ast_identifiers(handler)
        }
        self.assertIn("emit_sanitized_failure", handler_identifiers)
        self.assertIn("SystemExit", handler_identifiers)

    def test_optional_dependency_import_failures_are_sanitized(self):
        tree = ast.parse(
            SMOKE_SCRIPT.read_text(encoding="utf-8"), filename=str(SMOKE_SCRIPT)
        )
        import_guards = [
            node
            for node in tree.body
            if isinstance(node, ast.Try)
            and any(
                (isinstance(child, ast.Import) and
                 any(alias.name == "psutil" for alias in child.names))
                or (isinstance(child, ast.ImportFrom) and child.module == "pywinauto")
                for statement in node.body
                for child in ast.walk(statement)
            )
        ]

        self.assertEqual(len(import_guards), 1)
        guard = import_guards[0]
        self.assertTrue(any(
            isinstance(call.func, ast.Name)
            and call.func.id == "emit_sanitized_failure"
            for handler in guard.handlers
            for call in ast.walk(handler)
            if isinstance(call, ast.Call)
        ))
        self.assertTrue(any(
            isinstance(node, ast.Raise)
            and isinstance(node.exc, ast.Call)
            and isinstance(node.exc.func, ast.Name)
            and node.exc.func.id == "SystemExit"
            for handler in guard.handlers
            for node in ast.walk(handler)
        ))

    def test_previous_result_is_invalidated_before_a_new_smoke(self):
        invalidate = load_function("invalidate_previous_result")
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / "result.json"
            record.write_text('{"pass": true}', encoding="utf-8")

            invalidate(record)

            self.assertFalse(record.exists())

    def test_deletion_failure_cannot_leave_a_previous_pass_current(self):
        invalidate = load_function("invalidate_previous_result")

        class DeleteDeniedPath:
            def __init__(self):
                self.content = '{"pass": true}'

            def exists(self):
                return True

            def write_text(self, content, **_kwargs):
                self.content = content

            def unlink(self, **_kwargs):
                raise PermissionError("delete denied")

        current = DeleteDeniedPath()
        with self.assertRaises(PermissionError):
            invalidate(current)

        self.assertNotIn('"pass": true', current.content)
        self.assertIn('"pass": false', current.content)

    def test_previous_result_is_invalidated_before_optional_dependencies_and_output_setup(self):
        tree = ast.parse(
            SMOKE_SCRIPT.read_text(encoding="utf-8"), filename=str(SMOKE_SCRIPT)
        )
        invalidate_line = next(
            call.lineno
            for node in tree.body
            for call in ast.walk(node)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "invalidate_previous_result"
        )
        optional_import_lines = [
            node.lineno
            for node in ast.walk(tree)
            if (
                isinstance(node, ast.Import)
                and any(alias.name == "psutil" for alias in node.names)
            )
            or (
                isinstance(node, ast.ImportFrom)
                and node.module in {"PIL", "pywinauto"}
            )
        ]
        output_setup_line = next(
            call.lineno
            for node in tree.body
            for call in ast.walk(node)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "mkdir"
        )

        self.assertTrue(optional_import_lines)
        self.assertLess(invalidate_line, min(optional_import_lines))
        self.assertLess(invalidate_line, output_setup_line)

    def test_smoke_uses_one_shot_suppression_without_registry_mutation(self):
        tree = ast.parse(
            SMOKE_SCRIPT.read_text(encoding="utf-8"), filename=str(SMOKE_SCRIPT)
        )
        calls = [
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        ]
        set_value_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "SetValueEx"
        ]
        popen_calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "Popen"
        ]

        self.assertEqual(set_value_calls, [])
        self.assertNotIn("restore_registry_value_if_unchanged", calls)
        self.assertNotIn("restore_registry_tree", calls)
        self.assertNotIn("restore_credentials", calls)
        self.assertEqual(len(popen_calls), 1)
        launch = popen_calls[0].args[0]
        self.assertIsInstance(launch, ast.List)
        self.assertTrue(
            any(
                isinstance(element, ast.Constant)
                and element.value == "--no-autostart-once"
                for element in launch.elts
            )
        )

    def test_policy_helpers_remain_connected_to_fail_closed_gate(self):
        tree = ast.parse(
            SMOKE_SCRIPT.read_text(encoding="utf-8"), filename=str(SMOKE_SCRIPT)
        )
        direct_calls = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        enum_windows_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "EnumWindows"
        ]
        pass_assignments = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Name)
                and target.value.id == "record"
                and subscript_constant_value(target) == "pass"
                for target in node.targets
            )
        ]

        self.assertTrue({
            "invalidate_previous_result",
            "run_cleanup_steps",
            "evaluate_top_windows",
            "evaluate_executable_hash",
        }.issubset(direct_calls))
        self.assertGreaterEqual(len(enum_windows_calls), 2)
        self.assertEqual(len(pass_assignments), 1)
        gate_node = pass_assignments[0].value
        self.assertIsInstance(gate_node, ast.BoolOp)
        self.assertIsInstance(gate_node.op, ast.And)
        self.assertFalse(any(isinstance(node, ast.Or) for node in ast.walk(gate_node)))
        gate = ast_identifiers(gate_node)
        for required in (
            "cleanup_errors",
            "status",
            "executable_hash",
            "auto_start_restored",
            "credential_state_restored",
            "persisted_state",
            "after_processes",
            "after_connections",
        ):
            self.assertIn(required, gate)

        smoke_try = next(
            node for node in tree.body
            if isinstance(node, ast.Try)
            and any(
                isinstance(call.func, ast.Attribute) and call.func.attr == "Popen"
                for call in ast.walk(node)
                if isinstance(call, ast.Call)
            )
        )
        invalidate_statement = next(
            node for node in tree.body
            if any(
                isinstance(call.func, ast.Name)
                and call.func.id == "invalidate_previous_result"
                for call in ast.walk(node)
                if isinstance(call, ast.Call)
            )
        )
        self.assertLess(tree.body.index(invalidate_statement), tree.body.index(smoke_try))
        self.assertTrue(any(
            isinstance(call.func, ast.Name) and call.func.id == "run_cleanup_steps"
            for node in smoke_try.finalbody
            for call in ast.walk(node)
            if isinstance(call, ast.Call)
        ))

        named_assignments = {
            target.id: node.value
            for node in ast.walk(smoke_try)
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Name)
        }
        self.assertEqual(named_assignments["top_window_observation"].func.id, "evaluate_top_windows")
        self.assertIn(
            "top_window_observation",
            ast_identifiers(named_assignments["error_top_windows"]),
        )
        status_dict = next(
            node for node in ast.walk(smoke_try)
            if isinstance(node, ast.Dict)
            and any(isinstance(key, ast.Constant) and key.value == "status" for key in node.keys)
        )
        status_value = next(
            value for key, value in zip(status_dict.keys, status_dict.values)
            if isinstance(key, ast.Constant) and key.value == "status"
        )
        self.assertIn("top_window_observation", ast_identifiers(status_value))

        exit_statement = next(node for node in tree.body if isinstance(node, ast.Raise))
        self.assertIsInstance(exit_statement.exc, ast.Call)
        self.assertIsInstance(exit_statement.exc.func, ast.Name)
        self.assertEqual(exit_statement.exc.func.id, "SystemExit")
        self.assertEqual(len(exit_statement.exc.args), 1)
        exit_code = exit_statement.exc.args[0]
        self.assertIsInstance(exit_code, ast.IfExp)
        self.assertIsInstance(exit_code.body, ast.Constant)
        self.assertEqual(exit_code.body.value, 0)
        self.assertIsInstance(exit_code.orelse, ast.Constant)
        self.assertEqual(exit_code.orelse.value, 1)
        self.assertIsInstance(exit_code.test, ast.Call)
        self.assertIsInstance(exit_code.test.func, ast.Attribute)
        self.assertIsInstance(exit_code.test.func.value, ast.Name)
        self.assertEqual(exit_code.test.func.value.id, "record")
        self.assertEqual(exit_code.test.func.attr, "get")
        self.assertEqual(len(exit_code.test.args), 1)
        self.assertIsInstance(exit_code.test.args[0], ast.Constant)
        self.assertEqual(exit_code.test.args[0].value, "pass")

    def test_policy_rejects_bypassed_gate_and_unconditional_success_exit(self):
        original_script = globals()["SMOKE_SCRIPT"]
        original_source = original_script.read_text(encoding="utf-8")
        mutations = (
            original_source.replace(
                '    record["pass"] = (\n',
                '    record["pass"] = True or (\n',
                1,
            ),
            original_source.replace(
                'raise SystemExit(0 if record.get("pass") else 1)',
                'raise SystemExit(0)',
                1,
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            for index, mutation in enumerate(mutations):
                mutated_script = Path(directory) / f"mutated-smoke-{index}.py"
                mutated_script.write_text(mutation, encoding="utf-8")
                globals()["SMOKE_SCRIPT"] = mutated_script
                result = unittest.TestResult()
                try:
                    self.__class__(
                        "test_policy_helpers_remain_connected_to_fail_closed_gate"
                    ).run(result)
                finally:
                    globals()["SMOKE_SCRIPT"] = original_script
                self.assertFalse(
                    result.wasSuccessful(),
                    f"policy accepted fail-open mutation {index}",
                )

    def test_operational_markers_are_required_for_ui_observation(self):
        evaluate = load_function("evaluate_ui_observation")

        irrelevant = evaluate(["InputLeap", "Fechar"])
        observed = evaluate([
            "Pronto",
            "Pronto para conectar",
            "Escolha um modo e inicie o InputLeap.",
        ])

        self.assertFalse(irrelevant["pass"])
        self.assertEqual(
            irrelevant["missing"],
            ["pronto", "pronto para conectar", "escolha um modo e inicie o inputleap."],
        )
        self.assertTrue(observed["pass"])
        self.assertEqual(observed["missing"], [])

        blocked = evaluate([
            "Pronto", "Pronto para conectar", "Escolha um modo e inicie o InputLeap.",
            "Inicialização bloqueada",
        ])
        internal_error = evaluate([
            "Pronto", "Pronto para conectar", "Escolha um modo e inicie o InputLeap.",
            "Falha ao iniciar serviço",
        ])
        self.assertFalse(blocked["pass"])
        self.assertFalse(internal_error["pass"])

    def test_binary_provenance_requires_expected_release_hash(self):
        evaluate = load_function("evaluate_executable_hash")

        self.assertFalse(evaluate("abc", None)["pass"])
        self.assertFalse(evaluate("abc", "def")["pass"])
        self.assertTrue(evaluate("ABC", "abc")["pass"])

    def test_persisted_state_comparison_does_not_expose_snapshot_values(self):
        evaluate = load_function("evaluate_persisted_state")
        before = {"registry": {"values": [["sensitive", "[REDACTED]", 1]]}}

        unchanged = evaluate(before, before)
        changed = evaluate(before, {"registry": {"values": []}})

        self.assertTrue(unchanged["pass"])
        self.assertTrue(unchanged["registry_match"])
        self.assertFalse(changed["pass"])
        self.assertFalse(changed["registry_match"])
        self.assertNotIn("before", unchanged)
        self.assertNotIn("after", unchanged)
        self.assertNotIn("before", changed)
        self.assertNotIn("after", changed)

    def test_operational_failures_do_not_emit_sensitive_details(self):
        sanitize = load_function("sanitize_operational_failure")
        sensitive = r"C:\\Users\\person\\secret-token"
        failure = sanitize(OSError(sensitive))

        self.assertEqual(failure, {"status": "ERROR", "error_type": "OSError"})
        self.assertNotIn(sensitive, json.dumps(failure))

        tree = ast.parse(
            SMOKE_SCRIPT.read_text(encoding="utf-8"), filename=str(SMOKE_SCRIPT)
        )
        self.assertFalse(any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "str"
            and any(isinstance(argument, ast.Name) and argument.id == "error" for argument in node.args)
            for node in ast.walk(tree)
        ))
        smoke_try = next(
            node for node in tree.body
            if isinstance(node, ast.Try)
            and any(
                isinstance(call.func, ast.Attribute) and call.func.attr == "Popen"
                for call in ast.walk(node)
                if isinstance(call, ast.Call)
            )
        )
        sensitive_preflight_calls = {
            call.func.id
            for node in tree.body[:tree.body.index(smoke_try)]
            for call in ast.walk(node)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id in {
                "product_processes",
                "relevant_connections",
                "persisted_state_snapshot",
            }
        }
        self.assertEqual(sensitive_preflight_calls, set())
        self.assertTrue(any(
            isinstance(call.func, ast.Name)
            and call.func.id == "emit_sanitized_failure"
            for handler in smoke_try.handlers
            for call in ast.walk(handler)
            if isinstance(call, ast.Call)
        ))

    def test_sanitized_failure_console_cannot_emit_a_secondary_traceback(self):
        tree = ast.parse(
            SMOKE_SCRIPT.read_text(encoding="utf-8"), filename=str(SMOKE_SCRIPT)
        )
        emit_helpers = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "emit_sanitized_failure"
        ]
        self.assertEqual(len(emit_helpers), 1)
        emit_helper = emit_helpers[0]
        helper_guards = [node for node in emit_helper.body if isinstance(node, ast.Try)]
        self.assertEqual(len(helper_guards), 1)
        self.assertTrue(any(
            isinstance(node, ast.Pass)
            for handler in helper_guards[0].handlers
            for node in ast.walk(handler)
        ))

        error_handlers = [
            handler
            for node in ast.walk(tree)
            if isinstance(node, ast.Try)
            for handler in node.handlers
            if handler.name == "error"
        ]
        self.assertTrue(error_handlers)
        for handler in error_handlers:
            calls = [call for call in ast.walk(handler) if isinstance(call, ast.Call)]
            self.assertTrue(any(
                isinstance(call.func, ast.Name)
                and call.func.id == "emit_sanitized_failure"
                for call in calls
            ))
            self.assertFalse(any(
                isinstance(call.func, ast.Name) and call.func.id == "print"
                for call in calls
            ))

    def test_pass_record_is_not_published_before_console_finalization(self):
        tree = ast.parse(
            SMOKE_SCRIPT.read_text(encoding="utf-8"), filename=str(SMOKE_SCRIPT)
        )
        smoke_try = next(
            node
            for node in tree.body
            if isinstance(node, ast.Try)
            and any(
                isinstance(call.func, ast.Attribute) and call.func.attr == "Popen"
                for call in ast.walk(node)
                if isinstance(call, ast.Call)
            )
        )
        finalizer = next(node for node in smoke_try.finalbody if isinstance(node, ast.Try))
        print_index = next(
            index
            for index, statement in enumerate(finalizer.body)
            if any(
                isinstance(call.func, ast.Name) and call.func.id == "print"
                for call in ast.walk(statement)
                if isinstance(call, ast.Call)
            )
        )
        write_index = next(
            index
            for index, statement in enumerate(finalizer.body)
            if any(
                isinstance(call.func, ast.Attribute) and call.func.attr == "write_text"
                for call in ast.walk(statement)
                if isinstance(call, ast.Call)
            )
        )

        print_call = next(
            call
            for statement in finalizer.body
            for call in ast.walk(statement)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "print"
        )
        flush_keyword = next(
            (keyword for keyword in print_call.keywords if keyword.arg == "flush"), None
        )

        self.assertLess(print_index, write_index)
        self.assertIsNotNone(flush_keyword)
        self.assertIsInstance(flush_keyword.value, ast.Constant)
        self.assertTrue(flush_keyword.value.value)

    def test_final_record_io_failures_exit_without_raw_traceback(self):
        tree = ast.parse(
            SMOKE_SCRIPT.read_text(encoding="utf-8"), filename=str(SMOKE_SCRIPT)
        )
        smoke_try = next(
            node
            for node in tree.body
            if isinstance(node, ast.Try)
            and any(
                isinstance(call.func, ast.Attribute) and call.func.attr == "Popen"
                for call in ast.walk(node)
                if isinstance(call, ast.Call)
            )
        )
        protected_finalizers = [
            node
            for node in smoke_try.finalbody
            if isinstance(node, ast.Try)
            and any(
                isinstance(call.func, ast.Attribute) and call.func.attr == "write_text"
                for call in ast.walk(ast.Module(body=node.body, type_ignores=[]))
                if isinstance(call, ast.Call)
            )
            and any(
                isinstance(call.func, ast.Name) and call.func.id == "print"
                for call in ast.walk(ast.Module(body=node.body, type_ignores=[]))
                if isinstance(call, ast.Call)
            )
        ]

        self.assertEqual(len(protected_finalizers), 1)
        finalizer = protected_finalizers[0]
        self.assertTrue(any(
            isinstance(call.func, ast.Name)
            and call.func.id == "emit_sanitized_failure"
            for handler in finalizer.handlers
            for call in ast.walk(handler)
            if isinstance(call, ast.Call)
        ))
        self.assertTrue(any(
            isinstance(call.func, ast.Name)
            and call.func.id == "invalidate_previous_result"
            for handler in finalizer.handlers
            for call in ast.walk(handler)
            if isinstance(call, ast.Call)
        ))
        self.assertTrue(any(
            isinstance(node, ast.Raise)
            and isinstance(node.exc, ast.Call)
            and isinstance(node.exc.func, ast.Name)
            and node.exc.func.id == "SystemExit"
            for handler in finalizer.handlers
            for node in ast.walk(handler)
        ))

    def test_runtime_evidence_excludes_paths_addresses_and_pids(self):
        sanitize = load_function("sanitize_runtime_evidence")
        sensitive = r"C:\\Users\\person\\InputLeap\\input-leaps.exe"
        evidence = sanitize(
            [{"pid": 1234, "exe": sensitive}],
            [{"pid": 1234, "local": "10.0.0.1:24800", "remote": "10.0.0.2:50000"}],
        )

        self.assertEqual(evidence, {"process_count": 1, "connection_count": 1})
        serialized = json.dumps(evidence)
        self.assertNotIn(sensitive, serialized)
        self.assertNotIn("1234", serialized)
        self.assertNotIn("10.0.0.1", serialized)

        tree = ast.parse(
            SMOKE_SCRIPT.read_text(encoding="utf-8"), filename=str(SMOKE_SCRIPT)
        )
        record_dicts = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Dict)
            and any(
                isinstance(key, ast.Constant)
                and key.value in {"runtime_before", "runtime_after"}
                for key in node.keys
            )
        ]
        self.assertTrue(record_dicts)
        for record_dict in record_dicts:
            for key, value in zip(record_dict.keys, record_dict.values):
                if isinstance(key, ast.Constant) and key.value in {"runtime_before", "runtime_after"}:
                    self.assertIsInstance(value, ast.Call)
                    self.assertIsInstance(value.func, ast.Name)
                    self.assertEqual(value.func.id, "sanitize_runtime_evidence")

    def test_persisted_ui_evidence_contains_no_raw_text_or_screenshot(self):
        sanitize = load_function("sanitize_ui_evidence")
        sensitive = "PAIRING-CODE-MUST-NOT-PERSIST"
        evidence = sanitize(
            {"title": sensitive, "visible": True, "enabled": True, "rect": [1, 2, 3, 4]},
            [{"title": sensitive, "visible": True, "uia_texts": [sensitive]}],
            [sensitive],
            [sensitive],
        )

        serialized = json.dumps(evidence)
        self.assertNotIn(sensitive, serialized)
        self.assertEqual(evidence["top_window_count"], 1)
        self.assertEqual(evidence["child_text_count"], 1)
        self.assertEqual(evidence["uia_text_count"], 1)

        tree = ast.parse(
            SMOKE_SCRIPT.read_text(encoding="utf-8"), filename=str(SMOKE_SCRIPT)
        )
        self.assertFalse(any(
            isinstance(node, ast.ImportFrom) and node.module == "PIL"
            for node in tree.body
        ))


if __name__ == "__main__":
    unittest.main()
