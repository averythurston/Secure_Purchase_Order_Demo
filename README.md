# Secure Purchase Order Demo

## Setup Instructions

```bash
# 1. Clone the repository
git clone https://github.com/averythurston/Secure_Purchase_Order_Demo.git
cd Secure_Purchase_Order_Demo

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate RSA keys
python generate_keys.py

# 4. Initialize the database
python init_db.py

# 5. Run the application
python app.py