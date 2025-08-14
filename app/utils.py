# app/utils.py
from bson.objectid import ObjectId
from app.extensions import mongo

def _populate_admin_details(products):
    """
    Efficiently fetches admin details for a list of products.
    This avoids making a separate DB query for each product.
    """
    admin_ids = {product.get('adminId') for product in products if product.get('adminId')}
    if not admin_ids:
        return products

    # Convert string IDs to ObjectIds for the query
    admin_object_ids = [ObjectId(admin_id) for admin_id in admin_ids]
    
    # Fetch all required admins in a single query
    admins = mongo.db.admins.find(
        {"_id": {"$in": admin_object_ids}},
        {"name": 1, "phone": 1} # Projection to get only name and phone
    )

    # Create a mapping from admin ID to admin details
    admin_map = {str(admin['_id']): {"name": admin.get('name'), "phone": admin.get('phone')} for admin in admins}

    # Attach admin details to each product
    for product in products:
        admin_id = product.get('adminId')
        if admin_id in admin_map:
            product['adminDetails'] = admin_map[admin_id]
    
    return products