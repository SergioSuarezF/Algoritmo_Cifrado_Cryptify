from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class Encrypt(models.Model):
    dif_date = models.IntegerField
    mensaje_inicial = models.CharField(max_length=32)
    clave = models.CharField(max_length=32)
    len_clave_aes = models.IntegerField
    clave_inv_sep = models.CharField(max_length=64)
    mensaje_cifrado_aes = models.CharField(max_length=100)
    mensaje_cifrado_final = models.CharField(max_length=100)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    
    

    
    
    
