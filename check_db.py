
import sys
import os
from flask import Flask
from models.database import db, User, AnalysisSession, AttackLog

def check_db():
    # Adjust this path to match your app structure if needed
    from app import create_app
    app = create_app()
    with app.app_context():
        users = User.query.all()
        sessions = AnalysisSession.query.all()
        logs = AttackLog.query.all()
        
        print(f"Users: {len(users)}")
        for u in users:
            print(f" - {u.username} (Admin: {u.is_admin})")
            
        print(f"\nSessions: {len(sessions)}")
        for s in sessions:
            print(f" - {s.filename} (Status: {s.status}, Flows: {s.total_flows})")
            
        print(f"\nLogs: {len(logs)}")
        if logs:
            print(f" - Example: {logs[0].filename}, {logs[0].attack_category}")

if __name__ == "__main__":
    check_db()
