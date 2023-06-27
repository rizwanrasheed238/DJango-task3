
from django.contrib import messages, auth
from django.shortcuts import render, redirect, get_object_or_404

from .models import Account
from django.contrib.auth import authenticate

from django.contrib import messages

from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

from django.contrib.auth.tokens import default_token_generator



from datetime import timedelta, datetime
from django.utils import timezone
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from apiclient.discovery import build
from googleapiclient.errors import HttpError
from datetime import timedelta
import pickle
import sys


def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        user = authenticate(email=email, password=password)
        if user is not None:
            auth.login(request, user)
            messages.success(request, 'You are logged in.')
            request.session['email'] = email

            if user.is_admin:
                return redirect('/admin/')

            elif user.is_staff:
                return redirect('/seller/')

            else:
                return redirect('home')

        else:
            messages.error(request, 'Invalid login credentials.')
            return redirect('login')

    return render(request, 'login.html')


def register(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        fname = request.POST['fname']
        lname = request.POST['lname']
        phone_number = request.POST['phone']
        adrs = request.POST['adrs']
        city = request.POST['city']
        state = request.POST['state']
        pimg = request.FILES.get('pimg')
        pin = request.POST['pin']
        uname = request.POST['uname']

        cpassword = request.POST['cpassword']
        roles = request.POST['roles']
        is_user = is_staff = False

        if roles == 'Doctor':
            is_user = True
        else:
            is_staff = True

        if Account.objects.filter(email=email).exists():
            messages.error(request, 'email already exists')
            return redirect('login')
        elif password != cpassword:
            messages.error(request, 'password not matching')

            return redirect('login')


        else:
            user = Account.objects.create_user(email=email, password=password, fname=fname, lname=lname, roles=roles,
                                               phone_number=phone_number, Addres=adrs, city=city, state=state, pin=pin,
                                               username=uname, image=pimg, is_staff=is_staff, is_user=is_user)

            user.save()
            messages.success(request, 'you are registered')
            messages.success(request, 'Thank you for registering with us.')

            # current_site = get_current_site(request)
            # message = render_to_string('account_verification_email.html', {
            #     'user': user,
            #     'domain': current_site,
            #     'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            #     'token': default_token_generator.make_token(user),
            # })
            #
            # send_mail(
            #     'Please activate your account',
            #     message,
            #     'medievalstore3@gmail.com',
            #     [email],
            #     fail_silently=False,
            # )
            #
            # return redirect('/login/?command=verification&email=' + email)
            return redirect('login')
    return render(request, 'login.html')


def logout(request):
    auth.logout(request)
    return redirect('login')


def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Congratulations! Your account is activated.')
        return redirect('login')
    else:
        messages.error(request, 'Invalid activation link')
        return redirect('register')

def patient(request):
    return render(request,"patient.html")

def doctor(request):
    return render(request,"doctor.html")




def draft_list(request):
    drafts = blog.objects.filter(is_draft=True)
    return render(request, 'viewblog.html', {'drafts': drafts})

def viewblog(request):
    user = request.user
    blogpost=blog.objects.all()

    return render(request, "viewblog.html", {'blogpost': blogpost})

def blog(request):
    return render(request,"blog.html")


def booktoken(request, id):
    user = request.user
    appointment_duration = timedelta(minutes=45)
    service = build("calendar", "v3", credentials=credentials)

    doctor = get_object_or_404(Account, id=id)

    if request.method == 'POST':
        speciality = request.POST.get('speciality')
        date = request.POST.get('date')
        start_time = request.POST.get('start_time')

        appointment_datetime = datetime.strptime(date + ' ' + start_time, '%Y-%m-%d %H:%M')
        end_time = appointment_datetime + appointment_duration

        appointment = Appointment(
            doctor=doctor,
            patient=user,
            speciality=speciality,
            date=date,
            start_time=start_time,
            end_time=end_time.time()
        )
        appointment.save()

        event = (
            service.events()
            .insert(
                calendarId="primary",
                body={
                    "summary": speciality,

                    "start": {"dateTime": start_time.isoformat(),
                              'timeZone': timezone,

                              },
                    "end": {
                        "dateTime": end_time.isoformat(),
                        'timeZone': timezone,
                    },
                    "attendees": [{"email": doctor}

                                  ]
                },
            )
            .execute()
        )

        return render(request, "confirm.html", {'appointment': appointment})

    return render(request, "booktoken.html", {'doctor': doctor})


def doctorlist(request):
    doctors = Account.objects.filter(roles='Doctor')

    return render(request, "doctorlist.html", {'doctors': doctors})

def confirm(request):
    doctors=Appointment.objects.all()

    return render(request,"confirm.html",{'doctors':doctors})


def google_auth(request):
    flow = Flow.from_client_secrets_file(
        'path/to/client_secrets.json',
        scopes=['https://www.googleapis.com/auth/calendar.events'],
        redirect_uri=settings.GOOGLE_CALENDAR_REDIRECT_URI,
    )
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')

    # Save the state to the session
    request.session['google_auth_state'] = state

    return redirect(authorization_url)


def google_auth_callback(request):
    state = request.session.pop('google_auth_state', None)

    flow = Flow.from_client_secrets_file(
        'D:/client_secret.json',
        scopes=['https://www.googleapis.com/auth/calendar.events'],
        redirect_uri=settings.GOOGLE_CALENDAR_REDIRECT_URI,
    )

    authorization_response = request.build_absolute_uri()
    flow.fetch_token(authorization_response=authorization_response, state=state)

    credentials = flow.credentials
