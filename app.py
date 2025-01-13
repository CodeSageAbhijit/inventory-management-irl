import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required
from datetime import datetime, timedelta
from decorators import admin_required

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///inventory.db")

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route('/')
@login_required
def inventory():
    qr_code = request.args.get('qr_code')

    if 'scanned_items' not in session:
        session['scanned_items'] = []

    if qr_code:
        # Fetch the item from the database
        item = db.execute(
            "SELECT id, name, image_url, description, quantity FROM inventory_items WHERE qr_code = ?",
            qr_code
        )
        # print(items)

        if item:
                # Return the item as JSON for frontend consumption
            return jsonify({
                'id': item[0]['id'],
                'name': item[0]['name'],
                'image_url': item[0]['image_url'],
                'description': item[0]['description'],
                'quantity': item[0]['quantity']
            })
        else:
            return jsonify(None)  # Item not found

    # Pass the scanned items to the template
    return render_template('inventory.html', items=None)





@app.route('/add_to_cart', methods=['POST'])
@login_required
def add_to_cart():
    print("Form data received:", request.form)  # Debug print
    print("Raw request data:", request.get_data())  # Debug print

    user_id = session.get('user_id')
    item_ids = request.form.getlist('item_ids[]')

    print(f"User ID: {user_id}")  # Debug print
    print(f"Received item_ids: {item_ids}")  # Debug print

    if not item_ids:
        return jsonify({'error': 'No items selected'}), 400

    try:
        # Process each item
        for item_id in item_ids:
            item_id = int(item_id)
            # Check if item exists in cart
            existing_item = db.execute(
                "SELECT id, quantity FROM cart WHERE user_id = ? AND item_id = ?",
                user_id, item_id
            )

            if existing_item:
                # Update quantity
                new_quantity = existing_item[0]['quantity'] + 1
                db.execute(
                    "UPDATE cart SET quantity = ? WHERE id = ?",
                    new_quantity, existing_item[0]['id']
                )
            else:
                # Insert new item
                db.execute(
                    "INSERT INTO cart (user_id, item_id, quantity) VALUES (?, ?, ?)",
                    user_id, item_id, 1
                )

        return jsonify({'message': 'Items added to cart successfully'}), 200

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'error': 'Failed to add items to cart'}), 500




@app.route("/cart")
@login_required
def cart():
    user_id = session.get('user_id')  # Fetch the logged-in user's ID

    # Fetch items in the user's cart and include the duration field (set to 0 initially if not present)
    query = """
    SELECT ci.id, i.name, i.image_url, i.description, ci.quantity, ci.item_id, ci.duration
    FROM cart ci
    JOIN inventory_items i ON ci.item_id = i.id
    WHERE ci.user_id = ?
    """
    # Execute the query and fetch the cart items
    cart_items = db.execute(query, user_id)

    # If duration is None (for newly added items), set it to 0
    for item in cart_items:
        if item['duration'] is None:
            item['duration'] = 0

    # Calculate the total quantity
    total_quantity = sum(item['quantity'] for item in cart_items)

    # Render the cart page and pass the cart_items and total_quantity
    return render_template("cart.html", cart_items=cart_items, total_quantity=total_quantity)




@app.route('/update_cart_duration', methods=['POST'])
@login_required
def update_cart_duration():
    try:
        user_id = session.get('user_id')

        # Loop through the duration fields in the form
        for key, value in request.form.items():
            if key.startswith('duration_'):
                item_id = int(key.split('_')[1])  # Extract item_id from the key
                duration = int(value)  # Get the new duration value

                # Update the duration in the database for the item in the cart
                update_query = """
                UPDATE cart
                SET duration = ?
                WHERE user_id = ? AND item_id = ?
                """
                db.execute(update_query, duration, user_id, item_id)

        flash("Duration updated successfully.", "success")
    except Exception as e:
        flash(f"An error occurred while updating duration: {str(e)}", "danger")

    return redirect(url_for('cart'))  # Redirect back to the cart page

@app.route('/update_cart_quantity', methods=['POST'])
@login_required
def update_cart_quantity():
    try:
        user_id = session.get('user_id')

        # Loop through the quantity fields in the form
        for key, value in request.form.items():
            if key.startswith('quantity_'):
                item_id = int(key.split('_')[1])  # Extract item_id from the key
                quantity = int(value)  # Get the new quantity value

                # Fetch available stock for the item from inventory_items
                inventory_query = """
                SELECT quantity
                FROM inventory_items
                WHERE id = ?
                """
                inventory_item = db.execute(inventory_query, item_id)

                if not inventory_item:
                    flash(f"Item with ID {item_id} does not exist in inventory.", "danger")
                    continue

                available_stock = inventory_item[0]['quantity']  # Corrected to 'quantity'

                # Check if the requested quantity exceeds available stock
                if quantity > available_stock:
                    flash(f"Not enough stock available for item {item_id}. Available: {available_stock}, Requested: {quantity}.", "danger")
                elif quantity > 0:
                    # Update the quantity in the database for the item in the cart
                    update_query = """
                    UPDATE cart
                    SET quantity = ?
                    WHERE user_id = ? AND item_id = ?
                    """
                    db.execute(update_query, quantity, user_id, item_id)
                    flash(f"Quantity for item {item_id} updated successfully.", "success")
                else:
                    flash(f"Quantity must be greater than 0 for item {item_id}.", "danger")

    except Exception as e:
        flash(f"An error occurred while updating quantity: {str(e)}", "danger")

    return redirect(url_for('cart'))  # Redirect back to the cart page



@app.route('/remove_from_cart/<int:item_id>', methods=['POST'])
@login_required
def remove_from_cart(item_id):
    user_id = session.get('user_id')  # Get the logged-in user's ID
    quantity_to_remove = int(request.form.get('quantity', 0))  # Get the quantity to remove from the form

    # Fetch the current quantity of the item in the user's cart
    query = "SELECT quantity FROM cart WHERE user_id = ? AND item_id = ?"
    existing_item = db.execute(query, user_id, item_id)

    if existing_item:
        current_quantity = existing_item[0]['quantity']

        if quantity_to_remove >= current_quantity:
            # If the quantity to remove is equal to or greater than the current quantity, delete the item completely
            db.execute("DELETE FROM cart WHERE user_id = ? AND item_id = ?", user_id, item_id)
            flash('Item removed from cart.', 'success')
        else:
            # If the quantity to remove is less than the current quantity, update the quantity
            new_quantity = current_quantity - quantity_to_remove
            db.execute("UPDATE cart SET quantity = ? WHERE user_id = ? AND item_id = ?", new_quantity, user_id, item_id)
            flash(f'Removed {quantity_to_remove} of the item from the cart.', 'success')

    else:
        flash('Item not found in your cart.', 'error')

    return redirect(url_for('cart'))


@app.route('/request_items', methods=['POST'])
@login_required
def request_items():
    try:
        user_id = session.get('user_id')  # Get the current user ID

        # Fetch all cart items for this user
        cart_items_query = """
        SELECT * FROM cart WHERE user_id = ?
        """
        cart_items = db.execute(cart_items_query, user_id)

        # Iterate through the cart items and update their durations in the cart_requests table
        for item in cart_items:
            duration = item['duration'] if item['duration'] is not None else 0  # Default to 0 if duration is None
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Get current timestamp

            # Check if an entry already exists in cart_requests, if yes, update it, else insert a new one
            update_request_query = """
            INSERT INTO cart_requests (user_id, item_id, quantity, duration, status, timestamp)
            VALUES (?, ?, ?, ?, 'Pending', ?)
            ON CONFLICT(user_id, item_id) DO UPDATE SET
            quantity = excluded.quantity,
            duration = excluded.duration,
            status = 'Pending',
            timestamp = excluded.timestamp
            """
            db.execute(update_request_query, user_id, item['item_id'], item['quantity'], duration, timestamp)
            # Delete the items from the cart after they have been processed
            db.execute("""
                DELETE FROM cart WHERE user_id = ?
            """, user_id)
        flash("Request submitted successfully.", "success")
    except Exception as e:
        flash(f"An error occurred: {str(e)}", "danger")

    return redirect(url_for('cart'))  # Redirect back to the cart page







@app.route('/confirm_items', methods=['GET'])
@login_required
def confirm_items():
    user_id = session.get('user_id')

    # Fetch all approved requests for the user, including the duration
    query = """
    SELECT cr.id, cr.quantity, cr.duration, ii.name AS item_name
    FROM cart_requests cr
    JOIN inventory_items ii ON cr.item_id = ii.id
    WHERE cr.user_id = ? AND cr.status = 'Approved'
    """
    requests = db.execute(query, user_id)



    return render_template('confirm_items.html', requests=requests)



@app.route('/confirm_items', methods=['POST'])
@login_required
def confirm_selected_items():
    try:
        user_id = session.get('user_id')
        print("Request form data:", request.form)
        confirm_ids = request.form.getlist('confirm_ids[]')  # Selected request IDs
        print("Selected request IDs:", confirm_ids)

        if not confirm_ids:
            flash("No requests selected for confirmation.", "warning")
            return redirect(url_for('confirm_items'))

        for request_id in confirm_ids:
            # Get duration for each selected request
            duration_key = f"duration_{request_id}"
            duration = request.form.get(duration_key)
            print(f"Processing request ID {request_id} with duration {duration}")

            if not duration or int(duration) <= 0:
                flash(f"Invalid duration for request ID {request_id}.", "danger")
                return redirect(url_for('confirm_items'))

            # Fetch request details
            query = """
            SELECT item_id, quantity
            FROM cart_requests
            WHERE id = ? AND user_id = ? AND status = 'Approved'
            """
            request_details = db.execute(query, request_id, user_id)

            if not request_details:
                flash(f"Invalid request ID {request_id}.", "danger")
                return redirect(url_for('confirm_items'))

            # Handle inventory updates and database operations here...
            try:
                for detail in request_details:
                    item_id = detail['item_id']
                    requested_quantity = detail['quantity']

                    # Fetch current inventory quantity
                    inventory_query = "SELECT quantity FROM inventory_items WHERE id = ?"
                    inventory_quantity = db.execute(inventory_query, item_id)
                    inventory_quantity = int(inventory_quantity[0]['quantity'])

                    if not inventory_quantity:
                        print(f"Item with ID {item_id} not found in inventory.")
                        continue

                    current_quantity = inventory_quantity

                    # Check if sufficient stock is available
                    if current_quantity < requested_quantity:
                        print(f"Insufficient stock for item ID {item_id}. Requested: {requested_quantity}, Available: {current_quantity}")
                        continue

                    # Decrement inventory
                    update_query = "UPDATE inventory_items SET quantity = quantity - ? WHERE id = ?"
                    db.execute(update_query, requested_quantity, item_id)
                    print(f"Decremented {requested_quantity} from item ID {item_id}. New quantity: {current_quantity - requested_quantity}")



                # Update the borrowed status for confirmed requests
                update_borrowed_query = """
                UPDATE cart_requests
                SET borrowed = TRUE , status = 'Completed'
                WHERE id IN ({})
                """.format(','.join(['?'] * len(confirm_ids)))  # Dynamic query for multiple IDs
                db.execute(update_borrowed_query, *confirm_ids)
                print("Updated borrowed status to TRUE for selected requests.")

                # Delete the processed requests from cart_requests after inventory update
                # delete_query = """
                # DELETE FROM cart_requests WHERE id IN ({})
                # """.format(','.join(['?'] * len(confirm_ids)))  # Dynamic query for multiple IDs
                # db.execute(delete_query, *confirm_ids)
                # print("Deleted processed requests from cart_requests.")

                flash("Items confirmed and processed successfully.", "success")

            except Exception as e:
                print(f"An error occurred while updating inventory: {str(e)}")
                flash(f"An error occurred: {str(e)}", "danger")
                return redirect(url_for('confirm_items'))

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        flash(f"An error occurred: {str(e)}", "danger")
        return redirect(url_for('confirm_items'))

    return redirect(url_for('cart'))  # Redirect back to the cart page


@app.route('/borrowed')
@login_required
def borrowed_items():
    try:
        user_id = session.get('user_id')
        query = """
        SELECT
            ci.name,
            cr.quantity,
            julianday(cr.timestamp) + cr.duration - julianday('now') AS days_remaining,
            cr.return_status,
            cr.item_id,
            cr.timestamp,
            cr.duration
        FROM cart_requests cr
        JOIN inventory_items ci ON cr.item_id = ci.id
        WHERE cr.user_id = ? AND cr.status = 'Completed'
        """
        borrowed_items = db.execute(query, user_id)

        # Recalculate days_remaining using Python for better accuracy
        for item in borrowed_items:
            borrow_date = datetime.strptime(item['timestamp'], '%Y-%m-%d %H:%M:%S')
            duration = int(item['duration'])
            days_remaining = (borrow_date + timedelta(days=duration) - datetime.now()).days
            item['days_remaining'] = days_remaining if days_remaining > 0 else 0

        return render_template('borrowed.html', borrowed_items=borrowed_items)
    except Exception as e:
        flash(f"An error occurred while fetching borrowed items: {str(e)}", "danger")
        return redirect(url_for('cart'))



@app.route('/request_return/<int:item_id>', methods=['POST'])
@login_required
def request_return(item_id):
    try:
        user_id = session.get('user_id')

        # Update return_status to Waiting
        query = """
        UPDATE cart_requests
        SET return_status = 'Waiting'
        WHERE item_id = ? AND user_id = ? AND status = 'Completed'
        """
        db.execute(query, item_id, user_id)

        flash("Return request issued. Waiting for admin approval.", "success")
    except Exception as e:
        flash(f"An error occurred while requesting return: {str(e)}", "danger")

    return redirect(url_for('borrowed_items'))

# ADMIN FUNCTIONS



@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    if not session.get("is_admin"):
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('index'))

    # Fetch inventory summary for the dashboard
    inventory_summary = db.execute("SELECT * FROM inventory_items")
    return render_template('admin_dashboard.html', inventory=inventory_summary)


@app.route('/admin/inventory', methods=['GET', 'POST'])
@admin_required
def manage_inventory():
    """Manage Inventory"""
    if request.method == 'POST':
        # Get form data
        name = request.form.get('name')
        quantity = request.form.get('quantity')
        description = request.form.get('description', '')  # Default to empty string if not provided
        image_url = request.form.get('image_url', None)  # Default to None if not provided

        if not name or not quantity:
            flash("Name and quantity are required.", "danger")
        else:
            try:
                # Insert the item into the database, handling optional fields
                db.execute(
                    "INSERT INTO inventory_items (name, quantity, description, image_url) VALUES (?, ?, ?, ?)",
                    name, quantity, description, image_url
                )
                flash("Item added successfully.", "success")
            except Exception as e:
                flash(f"An error occurred while adding the item: {str(e)}", "danger")
        return redirect(url_for('manage_inventory'))

    # Fetch all inventory items
    try:
        inventory_items = db.execute("SELECT * FROM inventory_items")
    except Exception as e:
        flash(f"An error occurred while fetching the inventory items: {str(e)}", "danger")
        inventory_items = []  # Return an empty list in case of error

    return render_template('manage_inventory.html', inventory_items=inventory_items)




@app.route('/admin/edit_item/<int:item_id>', methods=['GET', 'POST'])
@admin_required
def edit_item(item_id):
    """Edit an existing inventory item"""

    # Fetch the item details from the database
    item = db.execute("SELECT * FROM inventory_items WHERE id = ?", item_id)

    if not item:
        flash("Item not found.", "danger")
        return redirect(url_for('manage_inventory'))

    item = item[0]  # Since execute returns a list of results, get the first (and only) one

    if request.method == 'POST':
        # Get form data
        name = request.form.get('name')
        quantity = request.form.get('quantity')
        description = request.form.get('description')
        image_url = request.form.get('image_url')

        # Ensure that required fields are filled
        if not name or not quantity:
            flash("Item name and quantity are required.", "danger")
        else:
            try:
                # Update item in database, only update non-empty fields
                query = "UPDATE inventory_items SET name = ?, quantity = ?"
                values = [name, quantity]

                # Add description to the query if provided
                if description:
                    query += ", description = ?"
                    values.append(description)

                # Add image_url to the query if provided
                if image_url:
                    query += ", image_url = ?"
                    values.append(image_url)

                query += " WHERE id = ?"
                values.append(item_id)

                db.execute(query, *values)
                flash("Item updated successfully.", "success")
                return redirect(url_for('manage_inventory'))

            except Exception as e:
                flash(f"An error occurred: {e}", "danger")

    return render_template('edit_item.html', item=item)



@app.route('/admin/delete_item/<int:item_id>', methods=['POST'])
@admin_required
def delete_item(item_id):
    """Set the quantity of an Inventory Item to 0"""
    try:
        # Update the item quantity to 0 in the database
        db.execute("UPDATE inventory_items SET quantity = 0 WHERE id = ?", item_id)
        flash("Item deleted successfully.", "success")
    except Exception as e:
        flash(f"An error occurred while updating the item: {str(e)}", "danger")
    return redirect(url_for('manage_inventory'))



@app.route('/admin/users')
@admin_required
def manage_users():
    """Manage Users"""
    users = db.execute("SELECT id, username, is_admin FROM users")
    return render_template('manage_users.html', users=users)


@app.route("/admin/promote_user/<int:user_id>", methods=["POST"])
@admin_required
def promote_user(user_id):
    """Promote a user to admin"""
    db.execute("UPDATE users SET is_admin = 1 WHERE id = ?", user_id)
    flash("User promoted to admin.", "success")
    return redirect(url_for('manage_users'))

@app.route("/admin/demote_user/<int:user_id>", methods=["POST"])
@admin_required
def demote_user(user_id):
    """Demote a user to regular user"""
    db.execute("UPDATE users SET is_admin = 0 WHERE id = ?", user_id)
    flash("User demoted to regular user.", "warning")
    return redirect(url_for('manage_users'))



@app.route('/admin/requests')
@admin_required
def manage_requests():
    """View Borrow/Return Requests"""
    borrow_requests = db.execute(
        """
        SELECT cr.id, ci.name, cr.quantity, u.username, cr.status, cr.return_status
        FROM cart_requests cr
        JOIN inventory_items ci ON cr.item_id = ci.id
        JOIN users u ON cr.user_id = u.id
        WHERE cr.status IN ('Pending', 'Completed') OR cr.return_status IN ('Waiting')
        """
    )
    return render_template('manage_requests.html', borrow_requests=borrow_requests)


@app.route('/admin/approve_borrow/<int:request_id>', methods=['POST'])
@admin_required
def approve_borrow(request_id):
    """Approve a borrow request"""
    try:
        # Update the status of the request to 'Approved' in the `cart_requests` table
        db.execute("UPDATE cart_requests SET status = 'Approved' WHERE id = ?", request_id)
        flash("Borrow request approved.", "success")
    except RuntimeError as e:
        flash(f"An error occurred while approving the borrow request: {e}", "danger")
    return redirect(url_for('manage_requests'))


@app.route('/admin/reject_borrow/<int:request_id>', methods=['POST'])
@admin_required
def reject_borrow(request_id):
    """Reject a borrow request"""
    try:
        # Update the status of the request to 'Rejected' in the `cart_requests` table
        db.execute("UPDATE cart_requests SET status = 'Rejected' WHERE id = ?", request_id)
        flash("Borrow request rejected.", "success")
    except RuntimeError as e:
        flash(f"An error occurred while rejecting the borrow request: {e}", "danger")
    return redirect(url_for('manage_requests'))


@app.route('/admin/approve_return/<int:request_id>', methods=['POST'])
@admin_required
def approve_return(request_id):
    """Approve a return request"""
    try:
        # Update the `returned` and `return_status` fields in the `cart_requests` table
        db.execute(
            "UPDATE cart_requests SET returned = 1, return_status = 'Approved' WHERE id = ?",
            request_id
        )
        flash("Return request approved.", "success")
    except RuntimeError as e:
        flash(f"An error occurred while approving the return request: {e}", "danger")
    return redirect(url_for('manage_return_requests'))

@app.route('/admin/reject_return/<int:request_id>', methods=['POST'])
@admin_required
def reject_return(request_id):
    """Reject a return request"""
    try:
        # Update the `return_status` in the `cart_requests` table to 'Rejected'
        db.execute(
            "UPDATE cart_requests SET return_status = 'Rejected' WHERE id = ?",
            request_id
        )
        flash("Return request rejected.", "success")
    except RuntimeError as e:
        flash(f"An error occurred while rejecting the return request: {e}", "danger")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/return_requests')
@admin_required
def manage_return_requests():
    """View and manage return requests"""
    return_requests = db.execute(
        """
        SELECT cr.id, ci.name, cr.quantity, u.username, cr.return_status
        FROM cart_requests cr
        JOIN inventory_items ci ON cr.item_id = ci.id
        JOIN users u ON cr.user_id = u.id
        WHERE cr.return_status IN ('Waiting')
        """
    )
    return render_template('return_requests.html', return_requests=return_requests)




@app.route('/admin/history', methods=['GET', 'POST'])
@admin_required
def view_history():
    filters = []

    user_id = request.args.get('user_id')
    username = request.args.get('username')
    item_name = request.args.get('item_name')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    # Construct the base query
    query = """SELECT h.*, u.username, i.name AS item_name
        FROM history h
        JOIN users u ON h.user_id = u.id
        JOIN inventory_items i ON h.item_id = i.id
        WHERE 1=1"""  # `1=1` ensures that the WHERE clause works even when no filter is applied

     # Apply filters based on user input
    if user_id:
        query += f" AND h.user_id = {user_id}"
    if username:
        query += f" AND u.username LIKE '%{username}%'"
    if item_name:
        query += f" AND i.name LIKE '%{item_name}%'"
    if start_date and end_date:
        query += f" AND h.timestamp BETWEEN '{start_date}' AND '{end_date}'"

    # Execute the query and fetch results
    history_records = db.execute(query)

    return render_template('history.html', history=history_records)




# @app.route('/process_returns', methods=['GET', 'POST'])
# @login_required
# def process_returns():
#     try:
#         # Query to fetch all 'Approved' return requests
#         approved_requests_query = """
#         SELECT id, item_id, quantity
#         FROM cart_requests
#         WHERE return_status = 'Approved'
#         """
#         approved_requests = db.execute(approved_requests_query)

#         if not approved_requests:
#             flash("No approved return requests to process.", "info")
#             return redirect(url_for('borrowed_items'))

#         for request in approved_requests:
#             request_id = request['id']
#             item_id = request['item_id']
#             returned_quantity = request['quantity']

#             # Update inventory
#             update_inventory_query = """
#             UPDATE inventory_items
#             SET quantity = quantity + ?
#             WHERE id = ?
#             """
#             db.execute(update_inventory_query, returned_quantity, item_id)

#             # Mark the request as completed
#             complete_request_query = """
#             UPDATE cart_requests
#             SET return_status = 'Completed'
#             WHERE id = ?
#             """
#             db.execute(complete_request_query, request_id)

#         flash("Inventory updated for all approved returns.", "success")
#     except Exception as e:
#         flash(f"An error occurred while processing returns: {str(e)}", "danger")

#     return redirect(url_for('borrowed_items'))





@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["is_admin"] = rows[0]["is_admin"]  # Store admin status in session

        # Redirect user based on role
        if session["is_admin"]:
            flash("Welcome, Admin!", "success")
            return redirect("/admin/dashboard")
        else:
            flash("Welcome back!", "success")
            return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    session.clear()

    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("password doesn't match!", 400)

        rows = db.execute(
            "SELECT * FROM users WHERE username= ?", request.form.get("username")
        )

        if len(rows) != 0:
            return apology("username already exists", 400)

        db.execute(
            "INSERT INTO users (username,hash) VALUES (?,?)",
            request.form.get("username"),
            generate_password_hash(request.form.get("password")),
        )

        # querying database for newly inserted user
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Remembering which user has logged in
        session["user_id"] = rows[0]["id"]

        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/changepassword", methods=["GET", "POST"])
@login_required
def changepassword():
    if request.method == "POST":
        password = request.form.get("newpassword")

        if not password:
            return apology("must provide new password", 403)

        user_id = session["user_id"]
        db.execute(
            "UPDATE users SET hash= ? WHERE id =?",
            generate_password_hash(password),
            user_id,
        )

        flash(" Password Change Successfully!!!")
        return redirect("/")
    else:
        return render_template("changepassword.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")
