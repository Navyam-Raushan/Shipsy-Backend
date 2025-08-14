# app/routes/customer_routes.py
from flask import Blueprint, request, jsonify
from bson.objectid import ObjectId
import logging

from app.extensions import mongo, bcrypt
from app.middlewares.jwt import generate_access_token, generate_refresh_token
from app.schemas import CustomerSchema, LoginSchema
from app.utils import _populate_admin_details

customer_bp = Blueprint('customer_bp', __name__)

# --- Auth Routes ---

@customer_bp.route('/register', methods=['POST'])
def register_customer():
    """Registers a new customer."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body cannot be empty."}), 400

    errors = CustomerSchema().validate(data)
    if errors:
        return jsonify({"errors": errors}), 400

    name = data['name']
    if mongo.db.customers.find_one({"name": name}):
        return jsonify({"error": "Customer with this name already exists."}), 409

    try:
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        mongo.db.customers.insert_one({
            "name": name,
            "password": hashed_password,
            "phone": data['phone'],
            "role": "customer" # Assign role for clarity
        })
        return jsonify({"message": "Customer registered successfully."}), 201
    except Exception as e:
        logging.error(f"Error registering customer: {e}")
        return jsonify({"error": "Internal server error."}), 500

@customer_bp.route('/login', methods=['POST'])
def login_customer():
    """Logs in a customer and returns tokens."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body cannot be empty."}), 400

    errors = LoginSchema().validate(data)
    if errors:
        return jsonify({"errors": errors}), 400

    try:
        customer = mongo.db.customers.find_one({"name": data.get('name')})
        if not customer:
            return jsonify({"error": "Customer not found."}), 404

        if bcrypt.check_password_hash(customer['password'], data.get('password')):
            user_data = {
                "id": str(customer['_id']),
                "name": customer['name'],
                "role": customer.get('role', 'customer')
            }
            access_token = generate_access_token(user_data)
            refresh_token = generate_refresh_token(user_data)
            return jsonify({
                "message": "Login successful.",
                "accessToken": access_token,
                "refreshToken": refresh_token
            }), 200
        else:
            return jsonify({"error": "Invalid password."}), 401
    except Exception as e:
        logging.error(f"Error logging in customer: {e}")
        return jsonify({"error": "Internal server error."}), 500

# --- Public Product Viewing Routes ---

@customer_bp.route('/products', methods=['GET'])
def get_all_products():
    """Gets all products from all admins."""
    try:
        products = list(mongo.db.products.find())
        for p in products:
            p['_id'] = str(p['_id'])
        
        populated_products = _populate_admin_details(products)
        return jsonify({"products": populated_products, "totalProducts": len(populated_products)}), 200
    except Exception as e:
        logging.error(f"Error fetching all products: {e}")
        return jsonify({"error": "Internal server error."}), 500

@customer_bp.route('/products/men', methods=['GET'])
def get_men_products():
    """Gets all products in the 'Men' category."""
    try:
        products = list(mongo.db.products.find({"gender": "Men"}))
        for p in products:
            p['_id'] = str(p['_id'])
        
        populated_products = _populate_admin_details(products)
        return jsonify({"products": populated_products, "totalProducts": len(populated_products)}), 200
    except Exception as e:
        logging.error(f"Error fetching men products: {e}")
        return jsonify({"error": "Internal server error."}), 500

@customer_bp.route('/products/women', methods=['GET'])
def get_women_products():
    """Gets all products in the 'Woman' category."""
    try:
        products = list(mongo.db.products.find({"gender": "Woman"}))
        for p in products:
            p['_id'] = str(p['_id'])
        
        populated_products = _populate_admin_details(products)
        return jsonify({"products": populated_products, "totalProducts": len(populated_products)}), 200
    except Exception as e:
        logging.error(f"Error fetching women products: {e}")
        return jsonify({"error": "Internal server error."}), 500

@customer_bp.route('/products/search', methods=['GET'])
def search_products():
    """Searches for products by name (case-insensitive)."""
    query = request.args.get('query')
    if not query:
        return jsonify({"error": "Search query parameter is required."}), 400

    try:
        products = list(mongo.db.products.find({"name": {"$regex": query, "$options": "i"}}))
        for p in products:
            p['_id'] = str(p['_id'])
        
        populated_products = _populate_admin_details(products)
        return jsonify({
            "products": populated_products,
            "totalResults": len(populated_products),
            "searchQuery": query
        }), 200
    except Exception as e:
        logging.error(f"Error searching products: {e}")
        return jsonify({"error": "Internal server error."}), 500

@customer_bp.route('/products/<string:id>', methods=['GET'])
def get_product_by_id(id):
    """Gets a single product by its ID, with admin details."""
    try:
        product = mongo.db.products.find_one({"_id": ObjectId(id)})
        if not product:
            return jsonify({"error": "Product not found."}), 404
        
        product['_id'] = str(product['_id'])
        populated_product = _populate_admin_details([product]) # Use helper for consistency
        
        return jsonify({"product": populated_product[0]}), 200
    except Exception:
        return jsonify({"error": "Invalid product ID format."}), 400