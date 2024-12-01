# forms.py
from django import forms

class EncryptForm(forms.Form):
    message = forms.CharField(label="Mensaje a cifrar", widget=forms.Textarea(attrs={'rows': 4, 'cols': 50}))
    password = forms.CharField(label="Clave de cifrado", widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    #encrypted_message = forms.CharField(label="Mensaje cifrado", required=False, widget=forms.Textarea(attrs={'rows': 4, 'cols': 50, 'readonly': 'readonly'}))
    #iv = forms.CharField(label="IV", required=False, widget=forms.TextInput(attrs={'readonly': 'readonly'}))
