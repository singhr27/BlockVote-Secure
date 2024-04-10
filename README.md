# To Run

Please clone the git repository from the provided GitHub link to your local repository and follow the following steps:

1. Install the following dependencies:
    - flask
    - simplejson
    - pycryptodome
    - matplotlib
    - qrcode

    x If it says "Not Found - x library", we are not sure why pycryptodome does this, but to make this project work, please follow the path to the crypto library and rename it to Crypto to make sure standard libraries work properly.

    For example:

    - For Mac: `/Library/Frameworks/Python.framework/Versions/3.11/lib/python3.11/site-packages`
    - For Windows: `C:\\Users\\ID\\AppData\\Local\\Programs\\Python\\Python311\\Lib\\site-packages`

2. Please open at least two terminals and run `peer.py` and `simulate_voting.py` using the following commands:
    - `python peer.py`
    - `python simulate_voting.py`

3. Open a browser and navigate to the following URL: `http://localhost:5000`
