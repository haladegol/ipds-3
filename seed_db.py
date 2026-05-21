
import os
import random
from datetime import datetime, timedelta
from app import create_app
from models.database import db, User, AnalysisSession, AttackLog
from werkzeug.security import generate_password_hash

def seed_data():
    app = create_app()
    with app.app_context():
        # 1. Create admin user if not exists
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            admin = User(
                username="admin",
                email="admin@hades.ai",
                password_hash=generate_password_hash("admin123"),
                is_admin=True
            )
            db.session.add(admin)
            print("Created admin user.")
        
        # 2. Create sample sessions
        if AnalysisSession.query.count() == 0:
            for i in range(3):
                filename = f"network_traffic_sample_{i+1}.csv"
                status = "completed"
                total_flows = random.randint(5000, 15000)
                anomaly_count = int(total_flows * random.uniform(0.1, 0.3))
                normal_count = total_flows - anomaly_count
                
                # Create mock summary JSON
                summary = {
                    "total_flows": total_flows,
                    "normal_count": normal_count,
                    "anomaly_count": anomaly_count,
                    "normal_percentage": round(normal_count / total_flows * 100, 1),
                    "anomaly_percentage": round(anomaly_count / total_flows * 100, 1),
                    "category_distribution": {
                        "DOS+DDOS": int(anomaly_count * 0.4),
                        "BOTNET": int(anomaly_count * 0.15),
                        "INFILTRATION": int(anomaly_count * 0.1),
                        "WEB_ATTACKS": int(anomaly_count * 0.1),
                        "BRUTE_FORCE": int(anomaly_count * 0.25)
                    },
                    "specific_attack_distribution": {
                        "DoS-Hulk": int(anomaly_count * 0.2),
                        "DDoS-HOIC": int(anomaly_count * 0.2),
                        "Botnet-Ares": int(anomaly_count * 0.15),
                        "FTP-BruteForce": int(anomaly_count * 0.25),
                        "Infiltration-Dropbox": int(anomaly_count * 0.1),
                        "SQL-Injection": int(anomaly_count * 0.1)
                    },
                    "detected_by_stage2_1": int(anomaly_count * 0.92),
                    "detected_by_stage2_2": int(anomaly_count * 0.08)
                }
                
                session = AnalysisSession(
                    filename=filename,
                    user_id=admin.id,
                    status=status,
                    total_flows=total_flows,
                    normal_count=normal_count,
                    anomaly_count=anomaly_count,
                    results_json=json.dumps({"summary": summary, "per_flow": []}),
                    upload_time=datetime.now() - timedelta(days=i)
                )
                db.session.add(session)
                print(f"Created session: {filename}")
                
                # 3. Create some attack logs
                for _ in range(10):
                    cat = random.choice(["DOS+DDOS", "BOTNET", "INFILTRATION", "WEB_ATTACKS", "BRUTE_FORCE"])
                    atk = random.choice(["DoS-Hulk", "Botnet-Ares", "Infiltration-Dropbox", "SQL-Injection", "FTP-BruteForce"])
                    log = AttackLog(
                        user_id=admin.id,
                        session_id=session.id,
                        filename=filename,
                        total_flows=total_flows,
                        normal_count=normal_count,
                        anomaly_count=anomaly_count,
                        attack_category=cat,
                        specific_attack=atk,
                        severity=random.choice(["low", "medium", "high", "critical"]),
                        detected_by=random.choice(["stage2.1", "stage2.2"]),
                        category_confidence=random.uniform(0.85, 0.99),
                        timestamp=datetime.now() - timedelta(minutes=random.randint(1, 1000))
                    )
                    db.session.add(log)
            
            db.session.commit()
            print("Successfully seeded database with mock analysis data.")
        else:
            print("Database already has data. Skipping seed.")

if __name__ == "__main__":
    import json
    seed_data()
