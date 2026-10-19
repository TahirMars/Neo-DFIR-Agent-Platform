"""
StateGraph 构建。

多节点 Supervisor 循环架构：
    START → supervisor
              │
              ├─ 条件路由 (route_after_supervisor)
              │
              ├─ forensic_agent  ──┐
              ├─ sample_agent    ──┼─→ 回到 supervisor
              ├─ report_generator ─┼─→ END
              └─ general_chat    ──┴─→ END
"""
import logging

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from src.agents.chat import general_chat_node
from src.agents.forensic import forensic_agent_node
from src.agents.report import report_node
from src.agents.sample import sample_agent_node
from src.agents.supervisor import route_after_supervisor, supervisor_node
from src.core.config import get_settings
from src.graph.state import DFIRState

logger = logging.getLogger(__name__)


def build_dfir_graph() -> StateGraph:
    """构建 DFIR 多智能体 StateGraph（Supervisor 循环模式）。"""
    graph = StateGraph(DFIRState)

    graph.add_node("supervisor", supervisor_node)
    graph.add_node("forensic_agent", forensic_agent_node)
    graph.add_node("sample_agent", sample_agent_node)
    graph.add_node("report_generator", report_node)
    graph.add_node("general_chat", general_chat_node)

    graph.add_edge(START, "supervisor")

    graph.add_conditional_edges(
        "supervisor",
        route_after_supervisor,
        {
            "forensic_agent": "forensic_agent",
            "sample_agent": "sample_agent",
            "report_generator": "report_generator",
            "general_chat": "general_chat",
            END: END,
        },
    )

    graph.add_edge("forensic_agent", "supervisor")
    graph.add_edge("sample_agent", "supervisor")
    graph.add_edge("report_generator", END)
    graph.add_edge("general_chat", END)

    return graph


_compiled_graph = None
_compiled_graph_checkpointed = None


def get_compiled_graph():
    """获取编译后的图（单例缓存）。开启 langgraph_checkpoint_enabled 时使用内存 checkpointer。"""
    global _compiled_graph, _compiled_graph_checkpointed
    if get_settings().langgraph_checkpoint_enabled:
        if _compiled_graph_checkpointed is None:
            _compiled_graph_checkpointed = build_dfir_graph().compile(checkpointer=InMemorySaver())
        return _compiled_graph_checkpointed
    if _compiled_graph is None:
        _compiled_graph = build_dfir_graph().compile()
    return _compiled_graph
