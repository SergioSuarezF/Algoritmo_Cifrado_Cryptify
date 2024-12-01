from django.shortcuts import render
from django.contrib.auth.forms import UserCreationForm
#from django.http import HttpResponse

# Create your views here.
def helloworld(request):
    
    return render(request, 'signup.html', {
        'formulario': UserCreationForm,
    })