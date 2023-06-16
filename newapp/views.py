from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import *
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.contrib.sessions.backends.db import SessionStore
import re
from django.contrib.auth.hashers import make_password, check_password


#Authentication And Session generation
@api_view(['POST'])
@csrf_exempt
def Authentication(request):

    username=request.data.get('username')
    password=request.data.get('password')
    
    try:
        u = customtable.objects.filter(username=username)
        print(u)
        for i in u:
            if i.passwords==password:
                if i.Roles == "admin":
                    session=SessionStore()
                    session['username']=username
                    session['roles']=i.Roles
                    session.save()
                    response = Response({'status': 'Welcome '+i.first_name}, status=200)
                    response.set_cookie('sessionid', session.session_key)  # Set the session ID in the cookie
                    return response
                elif i.Roles=="employee":
                    session=SessionStore()
                    session['username']=username
                    session['roles']=i.Roles
                    session.save()
                    response = Response({'status': 'Welcome '+i.first_name}, status=200)
                    response.set_cookie('sessionid', session.session_key)  # Set the session ID in the cookie
                    return response
                else :
                    return Response({'status':'unauthorized'},status=400)
            else :
                return Response({'status': 'Invalid Username or Password'}, status=400)
    except :
        return Response({'status': 'unautherized'}, status=401)

#ADMIN
@api_view(['GET','POST','PUT','DELETE'])
def Admin(request):
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    password_pattern = r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$'
    username_pattern = r'^[a-zA-Z0-9_-]{3,16}$'

    #Creating USER 
    if request.method=='POST':
        session_id=request.COOKIES.get('sessionid')
        print(session_id)
        if session_id:
            session = SessionStore(session_key=session_id)
            auth = session.get('username')
            roles=session.get('roles')
            try:
                admin=customtable.objects.get(username=auth)
            except:
                return Response({"message":"No user Found"})
            username = request.data.get("username")
            if username is not None and username!=auth and roles=='admin':
                ud=customtable.objects.filter(username=username)
                if len(ud) !=0:
                    return Response({'status':'USERNAME ALREADY REGISTER'})
                else:
                    fname=request.data.get("first_name")
                    lname=request.data.get("last_name")
                    email=request.data.get("email")
                    password=request.data.get("password")
                    role=request.data.get("Roles")
                    u=customtable()
                    check=customtable.objects.all()
                    if re.match(email_pattern,email)  :
                        for i in check:
                            if email!=i.email:
                                u.first_name=fname
                                u.last_name=lname
                                u.email=email
                                u.Roles=role
                                u.creatby=admin.id
                            else:
                                return Response({'Message':'Email Already Registered'})
                    else:
                        return Response({'Message':'Please enter valid email'})
                    if re.match(username_pattern,username):
                        u.username=username 
                    else:
                        return Response({'Message':'Username should greater than 3 character and it can conaion numbers and special character'})   
                    if re.match(password_pattern,password):
                        u.passwords=make_password(password)
                        u.save()
                        return Response({'status':'created'},status=201)
                    else:
                        return Response({'Message':'Password should have at least 8 characters long\nContains at least one letter (uppercase or lowercase)\nContains at least one digit'})
        else:
            return Response({'Message':'You don\'t have access to this page.'},status=403)
    elif request.method=='GET':
            session_id=request.COOKIES.get('sessionid')
            if session_id:
                session = SessionStore(session_key=session_id)
                auth = session.get('username')
                roles=session.get('roles')
                print(roles)
                if roles=="admin":
                        try:
                            data= customtable.objects.all()
                            jason = [
                            {
                            'id':item.id,
                            'first_name': item.first_name,
                            'last_name': item.last_name,
                            'username': item.username,
                            'email': item.email,
                            'passwords': item.passwords,
                            'Roles': item.Roles,
                            }
                            for item in data
                            ]
                            return JsonResponse(jason, safe=False)
                        except:
                            return Response({'Message':'Server Down'},status=500)
                else:
                    return Response({"Message":"You don\'t have access to this page"})
            else:
                return Response({'Message':'Please Loggin'},status=400)
    elif request.method=='PUT':
        session_id=request.COOKIES.get('sessionid')
        print(session_id)
        if session_id:
            session = SessionStore(session_key=session_id)
            auth = session.get('username')
            roles=session.get('roles')
            username=request.data.get('username')
            try:
                admin=customtable.objects.get(username=auth)
            except:
                return Response({"message":"No user Found"})
            if username is not None and roles=="admin":
                up_id=request.data.get('id')
                fname=request.data.get("first_name")
                lname=request.data.get("last_name")
                email=request.data.get("email")
                password=request.data.get("password")
                role=request.data.get("Roles")

                upuser=customtable.objects.filter(id=up_id)
                if len(upuser)!=0:
                    for i in upuser:
                        if re.match(email_pattern,email):
                            i.first_name=fname
                            i.last_name=lname   
                            i.email=email
                        else:
                            return Response({'Message':'Please enter valid email'})
                        if re.match(username_pattern,username):
                            i.username=username
                        else:
                            return Response({'Message':'Username should greater than 3 character and it can contaion numbers and special character'})
                        if re.match(password_pattern,password):
                            i.passwords=make_password(password)
                            i.Roles=role
                            i.save()
                            return Response({"message":"updated",'status-code':200}, status=200)
                        else:
                            return Response({'Message':'Password should have at least 8 characters long Contains at least one letter (uppercase or lowercase)\nContains at least one digit'})
                else:
                    return Response({"message": "User not found",'status-code':404}, status=404)
            else:
                return Response({'Message':'Access Denied! You are unauthorized to perform this action on this','status-code':400},status=400)
        else:
            return Response({'Message':'Please Loggin','status-code':404},status=401)
    elif request.method=="DELETE":
        session_id=request.COOKIES.get('sessionid')
        print(session_id)
        if session_id:
            session = SessionStore(session_key=session_id)
            auth = session.get('username')
            roles=session.get('roles')
            if roles=="admin":
                del_id=request.data.get("id")
                deleteuser=customtable.objects.filter(id=del_id).delete()
                return Response(deleteuser)
            else:
                return Response({'Message':'Access denied! you cannot access this resource or do that operation!','status-code':400},status=400)
        else:
            return Response({'Message':'Please Loggin','status-code':401},status=401)
    else:
        return Response({'Message':"Bad Request No such action is available",'status-code':400})
    
#Employee 
@api_view(['GET','PUT'])
@csrf_exempt
def Employee(request):
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    password_pattern = r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$'
    username_pattern = r'^[a-zA-Z0-9_-]{3,16}$'
    if request.method=='GET':
            session_id=request.COOKIES.get('sessionid')
            print(session_id)
            if session_id:
                session = SessionStore(session_key=session_id)
                auth = session.get('username')
                roles=session.get('roles')
                user= customtable.objects.filter(username=auth)
                for i in user:    
                    if i.username is not None and roles=="employee":
                            try:
                                jason =[
                                {
                                'id':i.id,
                                'first_name': i.first_name,
                                'last_name': i.last_name,
                                'username': i.username,
                                'email': i.email,
                                'passwords': i.passwords,
                                'Roles': i.Roles,
                                }]
                                
                               
                                return JsonResponse(jason, safe=False)
                            except:
                                return Response({'Message':'Server Down'},status=500)
                else:
                    return Response({'Message':'Please Loggin','status-code':401},status=401)
    elif request.method=='PUT':
        session_id=request.COOKIES.get('sessionid')
        print(session_id)
        if session_id:
            session = SessionStore(session_key=session_id)
            auth = session.get('username')
            roles=session.get('roles')
            user= customtable.objects.filter(username=auth)
            for i in user:
                if i.username is not None and roles=="employee":
                    up_id=request.data.get('id')
                    fname=request.data.get("first_name")
                    lname=request.data.get("last_name")
                    email=request.data.get("email")
                    username=request.data.get("username")
                    password=request.data.get("password")
                    role=request.data.get("Roles")

                    if len(user)!=0:
                        if re.match(email_pattern,email):
                            i.first_name=fname
                            i.last_name=lname   
                            i.email=email
                        else:
                            return Response({'Message':'Please enter valid email'})
                        if re.match(username_pattern,username):
                            i.username=username
                        else:
                            return Response({'Message':'Username must be alphanumeric with no spaces or special characters.'})
                        if re.match(password_pattern,password):
                            i.passwords=make_password(password)
                            i.Roles=role
                            i.save()
                            return Response({"message":"updated"}, status=200)
                        else:
                            return Response({'Message':'Password should have at least 8 characters long\nContains at least one letter (uppercase or lowercase)\nContains at least one digit'})
                    
                    else:
                        return Response({"message": "User not found"}, status=404)
                else:
                    return Response({'Message':'Access Denied! You are unauthorized to perform this action on this','status-code':401},status=401)
        else:
            return Response({'Message':'Please Loggin','status-code':401},status=401)
        
#Logout and Destorying Session 
@api_view(['GET'])
def logout(request):
    if request.session.has_key('username'):
        del request.session['username'] 
    response = Response({'status': 'Logged out'}, status=200)
    response.delete_cookie('sessionid')  
    return response

from django.core import serializers
from django.core.paginator import Paginator
from django.shortcuts import render

@api_view(['GET'])
def listing(request):
    data = customtable.objects.all()
    paginator = Paginator(data, 5)  # Create a paginator with 5 items per page
    page_number = request.GET.get('page')  # Get the current page number from the request query parameters
    page_obj = paginator.get_page(page_number)  # Get the Page object for the current page number
    return render(request, 'Data.html', {'page_obj': page_obj})