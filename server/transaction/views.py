from rest_framework import response, decorators as rest_decorators, permissions as rest_permissions
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi


@swagger_auto_schema(
    method='post',
    operation_description="Handle payment for a subscription",
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'subscription_id': openapi.Schema(type=openapi.TYPE_STRING, description='The ID of the subscription to be paid for')
        },
        required=['subscription_id']
    ),
    responses={
        200: openapi.Response(
            description="Payment processed successfully",
        ),
        400: openapi.Response(
            description="Bad Request",
        ),
        401: openapi.Response(
            description="Unauthorized",
        )
    },
    tags=["Transaction"]
)
@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def paySubscription(request):
    return response.Response({"msg": "Success"}, 200)


@swagger_auto_schema(
    method='post',
    operation_description="List all subscriptions for the authenticated user",
    responses={
        200: openapi.Response(
            description="Successfully retrieved subscriptions",
        ),
        401: openapi.Response(
            description="Unauthorized",
        )
    },
    tags=["Transaction"]
)

@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def listSubscriptions(request):
    return response.Response({"msg": "Success"}, 200)
