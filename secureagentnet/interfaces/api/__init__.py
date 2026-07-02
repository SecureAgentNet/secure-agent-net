from .hitl_routes import router as hitl_router
from .behavior_routes import router as behavior_router
from .team_routes import router as team_router
from .key_routes import router as key_router
from .config_routes import router as config_router
from .report_routes import router as report_router
from .blog_routes import router as blog_router
from .dashboard_routes import router as dashboard_router

__all__ = [
    "hitl_router",
    "behavior_router",
    "team_router",
    "key_router",
    "config_router",
    "report_router",
    "blog_router",
    "dashboard_router",
]
