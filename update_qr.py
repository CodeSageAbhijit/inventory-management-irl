import os
import base64
from cs50 import SQL
import re

# Initialize the CS50 database connection
db = SQL("sqlite:///cloud.db")  # Update with your actual database path

# Function to sanitize component names to make them valid file names
def sanitize_filename(name):
    # Replace any invalid characters with underscores
    sanitized_name = re.sub(r'[\/:*?"<>|]', '_', name)
    return sanitized_name

# Function to convert component name to Base64
def generate_name_base64(component_name):
    # Sanitize the component name to make it a valid filename
    sanitized_name = sanitize_filename(component_name)

    # Encode the sanitized component name to Base64
    name_base64 = base64.b64encode(sanitized_name.encode("utf-8")).decode("utf-8")
    print(name_base64)

    return name_base64  # Return the Base64 encoded name

# Function to update the Base64-encoded component name in the database
def update_name_base64_in_db():
    # Fetch all components from the inventory_items table
    components = db.execute("SELECT id, name FROM inventory_items")

    for component in components:
        component_id = component['id']
        component_name = component['name']

        # Generate the Base64 string for the component's name
        name_base64 = generate_name_base64(component_name)

        # Update the database with the generated Base64 string
        db.execute("""
            UPDATE inventory_items
            SET qr_code = ?
            WHERE id = ?
        """, name_base64, component_id)
        print(f"Base64-encoded name for '{component_name}' saved and database updated.")

# Run the script to generate Base64-encoded component names and update the database
update_name_base64_in_db()
