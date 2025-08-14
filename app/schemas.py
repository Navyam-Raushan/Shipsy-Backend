# app/schemas.py
from marshmallow import Schema, fields, validate

class AdminSchema(Schema):
    """Schema for validating new admin registration data."""
    name = fields.Str(required=True, error_messages={"required": "Name is required."})
    password = fields.Str(required=True, error_messages={"required": "Password is required."})
    # Phone is a string to allow for various formats (+, -, etc.)
    phone = fields.Str(required=True, error_messages={"required": "Phone is required."})

class CustomerSchema(Schema):
    """Schema for validating new customer registration data."""
    name = fields.Str(required=True, error_messages={"required": "Name is required."})
    password = fields.Str(required=True, error_messages={"required": "Password is required."})
    phone = fields.Str(required=True, error_messages={"required": "Phone is required."})

class LoginSchema(Schema):
    """Schema for validating login data for both admins and customers."""
    name = fields.Str(required=True, error_messages={"required": "Name is required."})
    password = fields.Str(required=True, error_messages={"required": "Password is required."})

class ProductSchema(Schema):
    """
    Schema for validating new product data.
    This is the Python equivalent of your Mongoose Product schema.
    """
    name = fields.Str(required=True, error_messages={"required": "Name is required."})
    about = fields.Str(required=True, error_messages={"required": "About is required."})
    prize = fields.Float(required=True, error_messages={"required": "Prize is required."})
    gender = fields.Str(
        required=True,
        validate=validate.OneOf(["Men", "Woman"], error="Gender must be 'Men' or 'Woman'."),
        error_messages={"required": "Gender is required."}
    )
    image = fields.Str(required=True, error_messages={"required": "Image is required."})

    # Note on other fields from Mongoose:
    # - adminId and adminName: These are not part of the input validation schema
    #   because they are derived from the logged-in user's JWT (g.user)
    #   in the route logic itself.
    # - timestamps (createdAt, updatedAt): These are not automatically added
    #   by Marshmallow or PyMongo. If you need them, you would typically add
    #   a `createdAt` field manually when inserting the document. MongoDB's
    #   _id field already contains a creation timestamp if needed.