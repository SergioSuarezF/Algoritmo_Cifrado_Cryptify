from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth import login, logout, authenticate
from django.db import IntegrityError
import os
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
    

def signin(request):
    if request.method == 'GET':
        return render(request, 'signin.html', {
            'formulario': AuthenticationForm
        })
    else:
        user = authenticate(request, username=request.POST['username'], password=request.POST['password'])
        
        if user is None:
            return render(request, 'signin.html', {
                'formulario': AuthenticationForm,
                'error': 'El usuario o contraseña no es correcto'
            })
        else:
            login(request, user)
            return redirect('encrypt')
        
        #return render(request, 'signin.html', {
            #'formulario': AuthenticationForm
        #})


# views.py
from django.shortcuts import render
from .forms import EncryptForm
from .utils import generar_clave, calcular_diferencia_fecha_hora, cifrar_aes, cifrado_cesar, descifrar_aes, descifrado_cesar

def encrypt_view(request):
    if request.method == 'POST':
        form = EncryptForm(request.POST)
        if form.is_valid():
            mensaje = form.cleaned_data['message']
            password = form.cleaned_data['password']

            # Calcular la diferencia de fecha y hora
            diferencia = calcular_diferencia_fecha_hora()

            # Determinar el tamaño de la clave
            bits = 128  # Aquí puedes decidir si lo haces dinámico según la contraseña

            # Generar salt y clave
            salt = os.urandom(16)
            clave = generar_clave(password, salt, bits)

            # Cifrar el mensaje con AES
            mensaje_cifrado, iv = cifrar_aes(mensaje, clave)

            # Cifrar aún más el mensaje con el cifrado César
            mensaje_cifrado_final = cifrado_cesar(mensaje_cifrado, diferencia)

            # Descifrar el mensaje con el cifrado César
            mensaje_descifrado_cesar = descifrado_cesar(mensaje_cifrado_final, diferencia)

            # Descifrar el mensaje con AES
            mensaje_descifrado = descifrar_aes(mensaje_descifrado_cesar, clave, iv)

            # Pasar los datos al contexto
            return render(request, 'encrypt.html', {
                'form': form,
                'encrypted_message': mensaje_cifrado_final,
                'iv': iv,
                'decrypted_message': mensaje_descifrado
            })
    else:
        form = EncryptForm()

    return render(request, 'encrypt.html', {'form': form})



