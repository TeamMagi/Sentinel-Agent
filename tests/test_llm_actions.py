"""ProposeHypothesis şeması — 5 tip hizalaması + to_hypothesis akışı. Faz 0.2."""
import pytest
from pydantic import ValidationError

from pentestai.llm.actions import ProposeHypothesis

ALL_TYPES = ["idor", "bfla", "excessive_data_exposure", "injection", "state_change_authz"]


@pytest.mark.parametrize("t", ALL_TYPES)
def test_all_five_types_accepted_and_mapped(t):
    h = ProposeHypothesis(type=t, path_template="/api/x/{id}").to_hypothesis()
    assert h.type == t
    assert h.source == "llm"
    assert h.endpoint.path_template == "/api/x/{id}"


def test_injection_param_fields_flow_through():
    h = ProposeHypothesis(
        type="injection", path_template="/rest/products/search",
        param="q", param_location="query",
    ).to_hypothesis()
    assert h.param == "q"
    assert h.param_location == "query"


def test_state_change_method_flows_to_endpoint():
    h = ProposeHypothesis(
        type="state_change_authz", method="DELETE", path_template="/api/orders/{id}",
    ).to_hypothesis()
    assert h.endpoint.method == "DELETE"
    assert h.type == "state_change_authz"


def test_defaults_when_param_omitted():
    h = ProposeHypothesis(type="idor", path_template="/api/x/{id}").to_hypothesis()
    assert h.param is None
    assert h.param_location == "query"


def test_unknown_type_is_rejected():
    with pytest.raises(ValidationError):
        ProposeHypothesis(type="rce", path_template="/x")
