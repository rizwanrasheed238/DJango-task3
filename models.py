from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin




class MyAccountManager(BaseUserManager):
    def create_user(self, fname, lname, email, phone_number,is_staff,is_user,Addres=None,roles=None,city=None,state=None,pin=None,image=None,username=None,password=None):
        if not email:
            raise ValueError('User must have an email address')

        if not lname:
            raise ValueError('User must have an username')

        user = self.model(
            email=self.normalize_email(email),
            lname=lname,
            fname=fname,
            phone_number=phone_number,
            Addres=Addres,
            image=image,
            roles=roles,
            city=city,
            state=state,
            pin=pin,
            username=username,
            is_user=is_user,
            is_staff=is_staff,

        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, fname, email, lname, password, phone_number):
        user = self.create_user(
            email=self.normalize_email(email),
            fname=fname,
            password=password,
            lname=lname,
            phone_number=phone_number,


        )
        user.is_admin = True
        user.is_active = True
        user.is_staff = True
        user.is_user = True
        user.is_superadmin = True
        user.save(using=self._db)
        return user


role_choices = (('Doctor', 'Doctor'), ('Patient', 'Patient'), ('None', 'None'))


class Account(AbstractBaseUser, PermissionsMixin):
    id = models.AutoField(primary_key=True)
    fname = models.CharField(max_length=100, blank=True, null=True)
    lname = models.CharField(max_length=100, blank=True, null=True)
    email = models.EmailField(max_length=100, unique=True)
    username = models.CharField(max_length=100, blank=True, null=True)
    image = models.ImageField(upload_to='media/products', blank=True)
    phone_number = models.BigIntegerField(default=0)
    Addres = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    state = models.CharField(max_length=100, blank=True, null=True)
    pin = models.BigIntegerField(default=0)
    roles = models.CharField(max_length=100, choices=role_choices, default="")

    # required
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now_add=True)
    is_staff = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_superadmin = models.BooleanField(default=False)
    approved_staff = models.BooleanField(default=False)
    is_user = models.BooleanField(default=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['fname', 'lname', 'phone_number', ]

    objects = MyAccountManager()

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, add_label):
        return True

class blog(models.Model):
    user=models.ForeignKey(Account,on_delete=models.SET_NULL,null=True)
    title=models.CharField(max_length=250)
    image = models.ImageField(upload_to='products', blank=True)
    category=models.ForeignKey(Category2,on_delete=models.CASCADE)
    summary=models.TextField(blank=True)
    content=models.TextField(blank=True)
    is_draft = models.BooleanField(default=False)

    def __str__(self):
        return self.title


class Appointment(models.Model):
    # Fields for the appointment
    doctor = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='doctor_appointments')
    patient = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='patient_appointments')
    speciality = models.CharField(max_length=100)
    date = models.DateField()
    start_time = models.TimeField()
    end_time = models.TimeField()

    def __str__(self):
        return f"Appointment with {self.doctor} on {self.date} at {self.start_time}"
