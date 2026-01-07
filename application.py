import os
from cms import create_app

app = create_app()

if __name__ == "__main__":
    environment = os.getenv("FLASK_ENV", "production")  # default to 'production' if not set
    debug_mode = environment == "development"  # True if 'FLASK_ENV' is 'development', else False
    app.run(debug=debug_mode)
