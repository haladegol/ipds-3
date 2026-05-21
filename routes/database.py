"""Database Viewer routes — SQLite browser integrated into HADES dashboard.
Requires admin user account (no separate password).
"""
from functools import wraps
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from sqlalchemy import text, inspect, func
from models.database import db, AttackLog, AnalysisSession, SystemLog, User, BlockedIP, AlertConfig, SimulationResult

database_bp = Blueprint("database", __name__, url_prefix="/database")


from routes.auth import hades_root_required

@database_bp.route("/")
@database_bp.route("/explorer")
@hades_root_required
def explorer():
    """Show all database tables with row counts and schema."""
    inspector = inspect(db.engine)
    tables = []
    for table_name in inspector.get_table_names():
        columns = inspector.get_columns(table_name)
        # Get row count
        result = db.session.execute(text(f"SELECT COUNT(*) FROM {table_name}"))
        row_count = result.scalar()
        tables.append({
            "name": table_name,
            "columns": [{"name": c["name"], "type": str(c["type"])} for c in columns],
            "row_count": row_count,
        })
    return render_template("database/explorer.html", tables=tables)


@database_bp.route("/table/<table_name>")
@hades_root_required
def view_table(table_name):
    """View rows of a specific table with pagination and filtering."""
    # Security: only allow known tables
    allowed_tables = {
        "users", "attack_logs", "analysis_sessions", "system_logs",
        "blocked_ips", "alert_configs", "simulation_results",
    }
    if table_name not in allowed_tables:
        flash("Table not found.", "error")
        return redirect(url_for("database.explorer"))

    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 25, type=int)
    search = request.args.get("search", "").strip()
    sort_by = request.args.get("sort", "id")
    sort_dir = request.args.get("dir", "desc")

    # Get columns
    inspector = inspect(db.engine)
    columns = [c["name"] for c in inspector.get_columns(table_name)]

    # Validate sort column
    if sort_by not in columns:
        sort_by = "id"
    if sort_dir not in ("asc", "desc"):
        sort_dir = "desc"

    # Build query
    offset = (page - 1) * per_page

    # Count total
    count_query = f"SELECT COUNT(*) FROM {table_name}"
    if search and table_name != "users":
        search_clauses = []
        for col in columns:
            search_clauses.append(f"CAST({col} AS TEXT) LIKE :search")
        count_query += " WHERE " + " OR ".join(search_clauses)

    count_result = db.session.execute(
        text(count_query),
        {"search": f"%{search}%"} if search and table_name != "users" else {}
    )
    total = count_result.scalar()

    # Get rows
    data_query = f"SELECT * FROM {table_name}"
    if search and table_name != "users":
        search_clauses = []
        for col in columns:
            search_clauses.append(f"CAST({col} AS TEXT) LIKE :search")
        data_query += " WHERE " + " OR ".join(search_clauses)
    data_query += f" ORDER BY {sort_by} {sort_dir} LIMIT :limit OFFSET :offset"

    params = {"limit": per_page, "offset": offset}
    if search and table_name != "users":
        params["search"] = f"%{search}%"

    result = db.session.execute(text(data_query), params)
    rows = [dict(row._mapping) for row in result]

    # Redact password for users table
    if table_name == "users":
        for row in rows:
            if "password_hash" in row:
                row["password_hash"] = "********"

    total_pages = (total + per_page - 1) // per_page

    return render_template(
        "database/view_table.html",
        table_name=table_name,
        columns=columns,
        rows=rows,
        page=page,
        per_page=per_page,
        total=total,
        total_pages=total_pages,
        search=search,
        sort_by=sort_by,
        sort_dir=sort_dir,
    )

@database_bp.route("/toggle-mode", methods=["POST"])
@hades_root_required
def toggle_mode():
    from flask import session
    current_mode = session.get("db_write_mode", False)
    session["db_write_mode"] = not current_mode
    flash("Database Write Mode is now ACTIVE." if not current_mode else "Database returned to Read-Only mode.", "success" if not current_mode else "info")
    return redirect(request.headers.get("Referer") or url_for("database.explorer"))

@database_bp.route("/edit/<table>/<int:row_id>", methods=["POST"])
@hades_root_required
def edit_row(table, row_id):
    from flask import session
    if not session.get("db_write_mode"):
        flash("Read-Only mode is enforced. Toggle write mode to edit.", "error")
        return redirect(url_for("database.view_table", table_name=table))
        
    model_map = {
        "users": User,
        "attack_logs": AttackLog,
        "analysis_sessions": AnalysisSession,
        "system_logs": SystemLog,
        "blocked_ips": BlockedIP,
        "alert_configs": AlertConfig,
        "simulation_results": SimulationResult,
    }
    ModelClass = model_map.get(table)
    if not ModelClass:
        flash("Invalid table.", "error")
        return redirect(url_for("database.explorer"))
        
    record = db.session.get(ModelClass, row_id)
    if not record:
        flash("Record not found.", "error")
        return redirect(url_for("database.view_table", table_name=table))
        
    # Get form data and update
    valid_updates = 0
    debug_keys = []
    
    # Map all valid columns to lowercase snake_case for resilient matching
    valid_columns = {c.name.lower().replace(" ", "_"): c.name for c in ModelClass.__table__.columns}
    
    for raw_key, val in request.form.items():
        # Relax user input (e.g. "Rule Name", "Severity" -> "rule_name", "severity")
        search_key = raw_key.strip().lower().replace(" ", "_")
        
        actual_key = valid_columns.get(search_key)
        debug_keys.append(f"'{raw_key}' -> mapped to '{actual_key}'")
        
        if actual_key and actual_key != "id":
            col = ModelClass.__table__.columns.get(actual_key)
            if col is not None:
                try:
                    ptype = col.type.python_type
                    if ptype == bool:
                        val = str(val).lower() in ("true", "1", "t", "y", "yes", "on")
                    elif ptype == int:
                        val = int(val) if str(val).strip() else 0
                    elif ptype == float:
                        val = float(val) if str(val).strip() else 0.0
                except Exception as e:
                    debug_keys.append(f"Type error for {actual_key}: {str(e)}")
            
            try:
                setattr(record, actual_key, val)
                valid_updates += 1
            except Exception as e:
                debug_keys.append(f"Setattr error for {actual_key}: {str(e)}")
            
    if valid_updates == 0:
        db.session.add(SystemLog(level="ERROR", event="DB Edit Debug", details=f"Failed. Request keys: {debug_keys} | Raw form dict: {dict(request.form)}"))
        db.session.commit()
        flash(f"Update failed: Could not rigidly match column '{list(request.form.keys())[0] if request.form else 'null'}'. Please check spelling of the column.", "error")
        return redirect(url_for("database.view_table", table_name=table))
        
    db.session.commit()
    
    db.session.add(SystemLog(level="WARNING", event="Database Edit", details=f"User {current_user.username} edited {table} ID {row_id}."))
    db.session.commit()
    
    flash(f"Record {row_id} in {table} updated successfully.", "success")
    return redirect(url_for("database.view_table", table_name=table))


@database_bp.route("/attack-logs")
@hades_root_required
def attack_logs():
    """Dedicated attack logs viewer with advanced filtering."""
    page = request.args.get("page", 1, type=int)
    per_page = 20
    category_filter = request.args.get("category", "")
    severity_filter = request.args.get("severity", "")
    detected_by_filter = request.args.get("detected_by", "")

    query = AttackLog.query

    if category_filter:
        query = query.filter(AttackLog.attack_category == category_filter)
    if severity_filter:
        query = query.filter(AttackLog.severity == severity_filter)
    if detected_by_filter:
        query = query.filter(AttackLog.detected_by == detected_by_filter)

    query = query.order_by(AttackLog.timestamp.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    categories = [r[0] for r in db.session.query(AttackLog.attack_category).distinct()
                   .filter(AttackLog.attack_category.isnot(None)).all()]
    severities = [r[0] for r in db.session.query(AttackLog.severity).distinct().all()]

    from utils.stats import get_accurate_stats
    _acc = get_accurate_stats()
    total_logs_count = AttackLog.query.count()
    total_anomalies_count = _acc["total_anomalies"]

    return render_template(
        "database/attack_logs.html",
        logs=pagination,
        categories=categories,
        severities=severities,
        category_filter=category_filter,
        severity_filter=severity_filter,
        detected_by_filter=detected_by_filter,
        total_count=total_logs_count,
        total_anomalies=total_anomalies_count,
    )
