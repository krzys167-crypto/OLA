import uuid
import pytest
from app import agent_runtime as runtime
from app.tool_authorization import ToolScope, ToolAuthorizationError, REGISTERED_TOOLS
from app.database import SessionLocal
from app.models import Tenant


def tenant():
    value = uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=value,name='scope-tests')); db.commit()
    return value


@pytest.mark.parametrize('allowed', [(), ('safe_expression',), ('shell',), None, 'safe_expression'])
def test_scope_denied_before_model_or_tool(allowed, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('model or tool executed without full scope')
    monkeypatch.setattr(runtime, '_invoke_llm', forbidden)
    monkeypatch.setattr(runtime, '_safe_expression', forbidden)
    result = runtime.run_agent_task(tenant(), 'Calculate 17 * 23', allowed_tools=allowed)
    assert result['status'] == 'BLOCK'
    assert result['reason'] == 'TOOL_SCOPE_DENIED'
    assert result['execution'] == []


def test_nina_passes_exact_scope_without_widening(monkeypatch):
    from app.nina import NinaOrchestrator, NinaTask
    task = NinaTask.create(tenant(), 'Calculate 17 * 23', ['safe_expression'])
    result = NinaOrchestrator().execute(task)
    assert result['runtime']['reason'] == 'TOOL_SCOPE_DENIED'
    assert result['runtime']['execution'] == []


@pytest.mark.parametrize('role,allowed', [('codeact',('local_mcp_tool_registry.sha256',)),
                                        ('mcp_tool_use',('safe_expression',))])
def test_dispatch_rechecks_scope_even_without_preflight(role, allowed, monkeypatch):
    scope = ToolScope.create('t','task',allowed)
    monkeypatch.setattr(runtime,'_invoke_llm',lambda *a: pytest.fail('model invoked'))
    with pytest.raises(ToolAuthorizationError):
        runtime._execute_agent(role,'t','task',{},[],scope)


@pytest.mark.parametrize('tenant_id,task', [('other','task'), ('t','changed task')])
def test_scope_cannot_be_reused_for_other_context(tenant_id,task):
    scope = ToolScope.create('t','task',REGISTERED_TOOLS)
    with pytest.raises(ToolAuthorizationError):
        runtime._execute_agent('codeact',tenant_id,task,{},[],scope)


def test_input_list_mutation_does_not_expand_scope():
    requested = ['safe_expression']
    scope = ToolScope.create('t','task',requested)
    requested.append('local_mcp_tool_registry.sha256')
    with pytest.raises(ToolAuthorizationError):
        scope.require('local_mcp_tool_registry.sha256','t','task')


def test_complete_profile_runs_and_records_scope():
    result = runtime.run_agent_task(tenant(),'Calculate 17 * 23',allowed_tools=REGISTERED_TOOLS)
    assert result['status'] == 'VERIFIED'
    assert result['final_result'] == '391'
    assert all(row['authorized_tools'] == sorted(REGISTERED_TOOLS) for row in result['execution'])
