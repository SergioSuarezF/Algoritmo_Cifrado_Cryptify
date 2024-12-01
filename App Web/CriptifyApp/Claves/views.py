from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.contrib.auth import login, logout
from django.db import IntegrityError
#from django.http import HttpResponse

# Create your views here.
def home(request):
    return render(request, 'home.html')

def signup(request): 
    
    if request.method == 'GET':
        return render(request, 'signup.html', {
            'formulario': UserCreationForm
        })
    else:
        if request.POST['password1'] == request.POST['password2']:
            try:
                # Registrar usuario
                user = User.objects.create_user(username=request.POST['username'], password=request.POST['password1'])
                user.save()
                login(request, user)
                return redirect('encrypt')
            except IntegrityError:
                return render(request, 'signup.html', {
                    'formulario': UserCreationForm,
                    "error": 'El usuario ya existe'
                })
        return render(request, 'signup.html', {
            'formulario': UserCreationForm,
            "error": 'Las contraseñas no coinciden'
        })


def encrypt(request):
    return render(request, 'encrypt.html')
            

def signout(request):
    logout(request)
    return redirect('home')
    




