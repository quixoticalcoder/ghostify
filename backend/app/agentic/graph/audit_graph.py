from langgraph.graph import StateGraph, END

from app.agentic.state.audit_state import SecurityAuditState
from app.agentic.agents.code_scanner.agent import code_scanner_agent
from app.agentic.agents.api_mapper.agent import api_mapper_agent
from app.agentic.agents.logic_reasoner.agent import logic_reasoner_agent
from app.agentic.agents.attack_executor.agent import attack_executor_agent
from app.agentic.agents.validator.agent import validator_agent
from app.agentic.agents.reporter.agent import reporter_agent
from app.agentic.agents.code_fixer.agent import code_fixer_agent
from app.agentic.agents.summary_generator.agent import summary_generator_agent
from app.agentic.graph.routing import route_after_logic_reasoner

from app.core.constants import (
    CODE_SCANNER_AGENT,
    API_MAPPER_AGENT,
    LOGIC_REASONER_AGENT,
    ATTACK_EXECUTOR_AGENT,
    VALIDATOR_AGENT,
    REPORTER_AGENT,
    CODE_FIXER_AGENT,
    SUMMARY_GENERATOR_AGENT,
)


def build_audit_graph():
    """
    Build and return the LangGraph for the security audit with code fixing.
    """

    graph = StateGraph(SecurityAuditState)

    # ===============================
    # REGISTER NODES
    # ===============================
    graph.add_node(CODE_SCANNER_AGENT, code_scanner_agent)
    graph.add_node(API_MAPPER_AGENT, api_mapper_agent)
    graph.add_node(LOGIC_REASONER_AGENT, logic_reasoner_agent)
    graph.add_node(ATTACK_EXECUTOR_AGENT, attack_executor_agent)
    graph.add_node(VALIDATOR_AGENT, validator_agent)
    graph.add_node(REPORTER_AGENT, reporter_agent)
    graph.add_node(CODE_FIXER_AGENT, code_fixer_agent)

    # ===============================
    # DEFINE EDGES (LINEAR FLOW)
    # ===============================
    graph.set_entry_point(CODE_SCANNER_AGENT)

    graph.add_edge(CODE_SCANNER_AGENT, API_MAPPER_AGENT)
    graph.add_edge(API_MAPPER_AGENT, LOGIC_REASONER_AGENT)
    graph.add_conditional_edges(
        "logic_reasoner",
        route_after_logic_reasoner,
        {
            "run_executor": "attack_executor",
            "skip_executor": "validator",
        },
    )
    graph.add_edge(ATTACK_EXECUTOR_AGENT, VALIDATOR_AGENT)
    graph.add_edge(VALIDATOR_AGENT, REPORTER_AGENT)
    graph.add_edge(REPORTER_AGENT, CODE_FIXER_AGENT)

    graph.add_edge(CODE_FIXER_AGENT, END)

    return graph.compile()


def build_summary_graph():
    """
    Build and return the LangGraph for summary-only mode.
    
    This graph:
    - Runs the full audit pipeline
    - Stops at REPORTER (no code fixing)
    - Uses SUMMARY_GENERATOR to create human-readable report
    - LLM has NO file access, NO code generation capabilities
    """

    graph = StateGraph(SecurityAuditState)

    # ===============================
    # REGISTER NODES
    # ===============================
    graph.add_node(CODE_SCANNER_AGENT, code_scanner_agent)
    graph.add_node(API_MAPPER_AGENT, api_mapper_agent)
    graph.add_node(LOGIC_REASONER_AGENT, logic_reasoner_agent)
    graph.add_node(ATTACK_EXECUTOR_AGENT, attack_executor_agent)
    graph.add_node(VALIDATOR_AGENT, validator_agent)
    graph.add_node(REPORTER_AGENT, reporter_agent)
    graph.add_node(SUMMARY_GENERATOR_AGENT, summary_generator_agent)

    # ===============================
    # DEFINE EDGES (LINEAR FLOW)
    # ===============================
    graph.set_entry_point(CODE_SCANNER_AGENT)

    graph.add_edge(CODE_SCANNER_AGENT, API_MAPPER_AGENT)
    graph.add_edge(API_MAPPER_AGENT, LOGIC_REASONER_AGENT)
    graph.add_conditional_edges(
        "logic_reasoner",
        route_after_logic_reasoner,
        {
            "run_executor": "attack_executor",
            "skip_executor": "validator",
        },
    )
    graph.add_edge(ATTACK_EXECUTOR_AGENT, VALIDATOR_AGENT)
    graph.add_edge(VALIDATOR_AGENT, REPORTER_AGENT)
    graph.add_edge(REPORTER_AGENT, SUMMARY_GENERATOR_AGENT)

    graph.add_edge(SUMMARY_GENERATOR_AGENT, END)

    return graph.compile()


audit_app = build_audit_graph()
summary_app = build_summary_graph()
