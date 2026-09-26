# ShadowTrap - A Web Deception and Multi-Stage Attack Detection Framework

ShadowTrap is a local defensive-security research project that presents a fictional electronics storefront, ShadowMart, while recording interactions with deliberately planted deception resources. Its defender dashboard correlates events from a visitor session into an explainable multi-stage attack sequence.

The project is intended for local demonstrations and controlled educational evaluation. It uses synthetic data and does not require external services.

## Features

- Flask-based ShadowMart storefront with visible Home and About pages.
- Four deception stages: hidden-route reconnaissance, phantom-login credential probing, honeytoken interaction, and decoy-file access.
- SQLite event storage and per-session sequence correlation.
- Explainable stage names, confidence levels, and reasons displayed in a Streamlit dashboard.
- Local synthetic attack simulator for demonstrating the detection flow.
- Configurable SQLite path through the `SHADOWTRAP_DB` environment variable.

The detector assigns LOW confidence to two distinct stages, MEDIUM to three, and HIGH when all four stages are observed in one session.

## Technologies

- Python 3.9 or later
- Flask
- Streamlit
- SQLite
- pandas
- requests

## Project Structure

```text
shadowtrap/
├── app/
│   ├── dashboard.py   # Streamlit defender dashboard
│   ├── db.py          # SQLite path selection and schema initialization
│   ├── detector.py    # Event logging and attack-sequence correlation
│   └── webapp.py      # Flask storefront and deception routes
├── static/
│   └── style.css
├── templates/         # Storefront, login, panel, and error templates
├── attacker_sim.py    # Synthetic local demonstration traffic
├── requirements.txt
└── README.md
```

Runtime SQLite databases are local data and are intentionally excluded from Git.

## Setup

From the project root, create and activate a virtual environment, then install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1` instead.

## Run the Application

Open two terminals in the project root and activate the virtual environment in each.

Terminal 1, start the Flask storefront:

```bash
python -m app.webapp
```

The storefront is available at `http://127.0.0.1:5000`.

Terminal 2, start the defender dashboard:

```bash
python -m streamlit run app/dashboard.py
```

The dashboard is available at `http://localhost:8501`.

By default, the application stores data in `shadowtrap.db` in the project root. To use a separate database, set the same `SHADOWTRAP_DB` path in both terminals before starting each service. For example, on macOS/Linux:

```bash
export SHADOWTRAP_DB="$PWD/shadowtrap-demo.db"
python -m app.webapp
```

In the dashboard terminal, set the same path and launch Streamlit:

```bash
export SHADOWTRAP_DB="$PWD/shadowtrap-demo.db"
python -m streamlit run app/dashboard.py
```

The selected database is initialized with the required tables if they do not exist. Database files are ignored by Git so local evaluation data is not published.

## Demonstration

For the controlled synthetic attack demonstration, start Flask first, then run in another terminal:

```bash
python attacker_sim.py
```

The simulator targets `http://127.0.0.1:5000` and intentionally touches the deception routes. Do not use it during a benign-traffic evaluation.

## Tests and Validation

There is currently no automated test suite in the repository. A Python syntax/bytecode compilation check can be run with:

```bash
python -m compileall -q app attacker_sim.py
```

For a functional demonstration, run the Flask application, open the storefront and dashboard, then run the synthetic simulator and inspect the resulting event and sequence data in SQLite.

## Security and Educational Use

ShadowTrap is a deliberately deceptive local lab. The phantom login accepts submitted credentials, and the honeytoken and decoy records are fabricated demonstration values, not production secrets or real customer data. Keep the services bound to localhost and do not deploy this project or expose it to public networks without a separate security review and appropriate isolation. Do not enter real passwords or personal information.