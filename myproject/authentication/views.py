from rest_framework import viewsets
from rest_framework.response import Response
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import json
from drf_yasg import openapi
from rest_framework.decorators import action
from drf_yasg.utils import swagger_auto_schema
from rest_framework.parsers import MultiPartParser
from Crypto.Util.Padding import pad, unpad

import json
import pyseto
from pyseto import Key, Paseto


private_key_pem = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"
public_key_pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"


username = openapi.Parameter('username', openapi.IN_QUERY, description="username", type=openapi.TYPE_STRING,required=True) 
password = openapi.Parameter('password', openapi.IN_QUERY, description="password", type=openapi.TYPE_STRING,required=True) 



class TokenViewSet(viewsets.ViewSet):
    parser_classes         = (MultiPartParser, )


    @action(detail=True, methods=['post'])
    @swagger_auto_schema(manual_parameters = [username,password])
    def generate_token(self, request):
        try:

            
            username = request.query_params.get('username')
            password = request.query_params.get('password')
            
            # Authenticate user here (e.g., check username and password against database)
            # If authentication is successful, generate a PASETO token
            if username == 'test' and password == 'test':
                #One way

                # private_key = Key.new(version=4, purpose="public", key=private_key_pem)
                # paseto = Paseto.new(
                #             exp=36000, include_iat=True
                #         )  # Default values are exp=0(not specified) and including_iat=False
                
                # token = paseto.encode(
                #         private_key,
                #         {"email": "test@email.com", "password":"testpassword","phone":"9876543210"},
                #         serializer=json,
                #     )
                # return Response({'token': token})

                #Other way
                raw_key = Key.new(version=4, purpose="local", key=b"our-secret")
                token = pyseto.encode(
                    raw_key,
                    b'{"data": "this is a signed message", "exp": "2022-01-01T00:00:00+00:00"}',
                )

                sealed_key = raw_key.to_paserk(sealing_key=public_key_pem)
                return Response({'token': sealed_key})


            return Response({'error': 'Invalid credentials'}, status=401)
        except Exception as e:
            return Response({'error': str(e)})
    
    @action(detail=True, methods=['get'])
    def decode_token(self, request,token):
        try:
            
            # Authenticate user here (e.g., check username and password against database)
            # If authentication is successful, generate a PASETO token

            #One way

            # print("{==============================================}")
            # print(token)
            # print("{==============================================}")

            # public_key = Key.new(version=4, purpose="public", key=public_key_pem)
            # decoded = pyseto.decode(public_key, token, deserializer=json)
            # print("[================================================]")
            # print(decoded.payload)
            # print("[================================================]")
            # return Response({'token': decoded.payload})

            #other way

            unsealed_key = Key.from_paserk(token, unsealing_key=private_key_pem)
            decoded = pyseto.decode(unsealed_key, token)
            return Response({'token': decoded.payload})

        except Exception as e:
            return Response({'error': str(e)})
    
            
