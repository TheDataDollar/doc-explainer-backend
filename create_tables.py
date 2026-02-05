from db import Base, engine
import models  # this loads the User model

Base.metadata.create_all(bind=engine)
print("✅ Tables created!")
