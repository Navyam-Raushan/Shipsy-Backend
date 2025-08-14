# app/routes/admin_routes.py
from flask import Blueprint, request, jsonify, g
from functools import wraps
from bson.objectid import ObjectId, InvalidId
import logging

from app.extensions import mongo, bcrypt
from app.middlewares.jwt import (
    jwt_auth_middleware,
    generate_access_token,
    generate_refresh_token
)
# Import the new schema for validation
from app.schemas import ProductSchema, AdminSchema, LoginSchema
from app.utils import _populate_admin_details # Import the helper


admin_bp = Blueprint('admin_bp', __name__)

# --- Custom Decorator for Admin Role ---
def admin_required(f):
    """Ensures the logged-in user has the 'admin' role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # This decorator must be used *after* @jwt_auth_middleware
        if 'user' not in g or g.user.get('role') != 'admin':
            return jsonify({"error": "Administrator access required."}), 403
        return f(*args, **kwargs)
    return decorated_function

# --- Auth Routes ---

@admin_bp.route('/register', methods=['POST'])
def register_admin():
    """Registers a new admin user."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body cannot be empty."}), 400

    errors = AdminSchema().validate(data)
    if errors:
        return jsonify({"errors": errors}), 400

    name = data.get('name')

    if mongo.db.admins.find_one({"name": name}):
        return jsonify({"error": "Admin with this name already exists."}), 409

    try:
        password = data.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        mongo.db.admins.insert_one({
            "name": name,
            "password": hashed_password,
            "phone": data['phone'],
            "role": "admin"  # Assign role on registration
        })

        return jsonify({"message": "Admin registered successfully."}), 201
    except Exception as e:
        logging.error(f"Error registering admin: {e}")
        return jsonify({"error": "Internal server error."}), 500

@admin_bp.route('/login', methods=['POST'])
def login_admin():
    """Logs in an admin user and returns access/refresh tokens."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body cannot be empty."}), 400

    errors = LoginSchema().validate(data)
    if errors:
        return jsonify({"errors": errors}), 400

    try:
        admin = mongo.db.admins.find_one({"name": data.get('name')})

        if not admin:
            return jsonify({"error": "Admin not found."}), 404

        if bcrypt.check_password_hash(admin['password'], data.get('password')):
            user_data = {
                "id": str(admin['_id']),
                "name": admin['name'],
                "role": admin.get('role', 'admin') # Use 'role' consistently
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
        logging.error(f"Error logging in admin: {e}")
        return jsonify({"error": "Internal server error."}), 500

# --- Product Routes ---

@admin_bp.route('/products', methods=['POST'])
@jwt_auth_middleware
@admin_required
def add_product():
    """Adds a new product, accessible only by admins."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body cannot be empty."}), 400

    # Validate incoming data using the Marshmallow schema
    errors = ProductSchema().validate(data)
    if errors:
        return jsonify({"errors": errors}), 400
    
    # Check for product name uniqueness before inserting
    if mongo.db.products.find_one({"name": data['name']}):
        return jsonify({"error": f"A product with the name '{data['name']}' already exists."}), 409

    try:
        new_product = {
            "name": data['name'],
            "about": data['about'],
            "prize": data['prize'],
            "gender": data['gender'],
            "image": data['image'],
            "adminId": g.user['id'],
            "adminName": g.user['name']
        }
        result = mongo.db.products.insert_one(new_product)
        new_product['_id'] = str(result.inserted_id)
        
        return jsonify({
            "message": "Product added successfully.",
            "product": new_product
        }), 201
    except Exception as e:
        logging.error(f"Error adding product: {e}")
        return jsonify({"error": "Internal server error."}), 500

@admin_bp.route('/products/my-products', methods=['GET'])
@jwt_auth_middleware
@admin_required
def get_my_products():
    """Gets all products added by the logged-in admin."""
    try:
        products = list(mongo.db.products.find({"adminId": g.user['id']}))
        for product in products:
            product['_id'] = str(product['_id'])
        return jsonify({"products": products}), 200
    except Exception as e:
        logging.error(f"Error fetching admin products: {e}")
        return jsonify({"error": "Internal server error."}), 500

@admin_bp.route('/products/men', methods=['GET'])
def get_men_products():
    """Gets all products in the 'Men' category."""
    try:
        products = list(mongo.db.products.find({"gender": "Men"}))
        for product in products:
            product['_id'] = str(product['_id'])
        populated_products = _populate_admin_details(products)
        return jsonify({"products": populated_products}), 200
    except Exception as e:
        logging.error(f"Error fetching men products: {e}")
        return jsonify({"error": "Internal server error."}), 500

@admin_bp.route('/products/women', methods=['GET'])
def get_women_products():
    """Gets all products in the 'Woman' category."""
    try:
        products = list(mongo.db.products.find({"gender": "Woman"}))
        for product in products:
            product['_id'] = str(product['_id'])
        populated_products = _populate_admin_details(products)
        return jsonify({"products": populated_products}), 200
    except Exception as e:
        logging.error(f"Error fetching women products: {e}")
        return jsonify({"error": "Internal server error."}), 500

@admin_bp.route('/products/<string:id>', methods=['GET'])
def get_product_by_id(id):
    """Gets a single product by its ID."""
    try:
        product = mongo.db.products.find_one({"_id": ObjectId(id)})
        if not product:
            return jsonify({"error": "Product not found."}), 404
        product['_id'] = str(product['_id'])
        populated_product = _populate_admin_details([product])
        return jsonify({"product": populated_product[0]}), 200
    except Exception:
        return jsonify({"error": "Invalid product ID format."}), 400

@admin_bp.route('/products/update/<string:id>', methods=['PUT'])
@jwt_auth_middleware
@admin_required
def update_product(id):
    """Updates a product's details. Admin can only update their own products."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body cannot be empty."}), 400

    # Validate incoming data. `partial=True` allows for updating only some fields.
    errors = ProductSchema(partial=True).validate(data)
    if errors:
        return jsonify({"errors": errors}), 400

    # If the name is being updated, check if it conflicts with another product.
    if 'name' in data:
        existing_product = mongo.db.products.find_one({
            "name": data['name'],
            "_id": {"$ne": ObjectId(id)}  # Exclude the current product from the check
        })
        if existing_product:
            return jsonify({"error": f"Another product with the name '{data['name']}' already exists."}), 409

    try:
        result = mongo.db.products.update_one(
            {"_id": ObjectId(id), "adminId": g.user['id']},
            {"$set": data}
        )
        if result.matched_count == 0:
            return jsonify({"error": "Product not found or you don't have permission to update it."}), 404
        return jsonify({"message": "Product updated successfully."}), 200
    except InvalidId:
        return jsonify({"error": "Invalid product ID format."}), 400

@admin_bp.route('/products/delete/<string:id>', methods=['DELETE'])
@jwt_auth_middleware
@admin_required
def delete_product(id):
    """Deletes a product. Admin can only delete their own products."""
    try:
        result = mongo.db.products.delete_one({"_id": ObjectId(id), "adminId": g.user['id']})
        if result.deleted_count == 0:
            return jsonify({"error": "Product not found or you don't have permission to delete it."}), 404
        return jsonify({"message": "Product deleted successfully."}), 200
    except InvalidId:
        return jsonify({"error": "Invalid product ID format."}), 400