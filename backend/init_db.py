from database import engine, Base
import models

print("Initializing My_Scanner database schema...")
Base.metadata.create_all(bind=engine)
print("Database initialized successfully! All tables created.")