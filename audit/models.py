from django.db import models
from django.contrib.auth.models import (
BaseUserManager, AbstractBaseUser, PermissionsMixin
)
from django.utils.translation import ugettext_lazy as _
from django.utils.safestring import mark_safe
# Create your models here.


class Host(models.Model):
    '''
    主机信息
    '''
    hostname = models.CharField(max_length=24)
    ip_addr = models.GenericIPAddressField(unique=True)
    port = models.PositiveIntegerField(default=22)
    idc = models.ForeignKey("IDC")
    enabled = models.BooleanField(default=True)

    def __str__(self):
        return "%s:%s" % (self.hostname, self.ip_addr)

class IDC(models.Model):
    """
    数据中心信息
    """
    name = models.CharField(max_length=64)

    def __str__(self):
        return self.name


class HostGroup(models.Model):
    """
    主机组
    """
    name = models.CharField(max_length=64, unique=True)
    bind_hosts = models.ManyToManyField("BindHost", blank=True)

    def __str__(self):
        return self.name


class UserProfileManager(BaseUserManager):
    def create_user(self, email, name, password=None):
        """
        Creates and saves a User with the given email, date of
        birth and password.
        """
        if not email:
            raise ValueError('Users must have an email address')

        user = self.model(
            email=self.normalize_email(email),
            name=name,
        )

        user.set_password(password)
        self.is_active = True
        user.save(using=self._db)
        return user

    def create_superuser(self,email, name, password):
        """
        Creates and saves a superuser with the given email, date of
        birth and password.
        """
        user = self.create_user(
            email,
            password=password,
            name=name,
        )
        user.is_active = True
        user.is_superuser = True
        #user.is_admin = True
        user.save(using=self._db)
        return user



class UserProfile(AbstractBaseUser,PermissionsMixin):
    """堡垒机账号"""
    email = models.EmailField(
        verbose_name='email address',
        max_length=255,
        unique=True,
        null=True
    )
    password = models.CharField(_('password'), max_length=128,
                                help_text=mark_safe('''<a href='password/'>修改密码</a>'''))
    name = models.CharField(max_length=32)
    is_active = models.BooleanField(default=True)
    #is_admin = models.BooleanField(default=False)

    bind_hosts = models.ManyToManyField("BindHost",blank=True)
    host_groups = models.ManyToManyField("HostGroup",blank=True)

    objects = UserProfileManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']

    def get_full_name(self):
        # The user is identified by their email address
        return self.email

    def get_short_name(self):
        # The user is identified by their email address
        return self.email

    def __str__(self):              # __unicode__ on Python 2
        return self.email

    # def has_perm(self, perm, obj=None):
    #     "Does the user have a specific permission?"
    #     # Simplest possible answer: Yes, always
    #     return True
    #
    # def has_module_perms(self, app_label):
    #     "Does the user have permissions to view the app `app_label`?"
    #     # Simplest possible answer: Yes, always
    #     return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_active


class HostUser(models.Model):
    """
    主机登录用户
    """
    auth_type_choices = ((0, 'ssh-password'), (1, 'ssh-key'))
    auth_type = models.SmallIntegerField(choices=auth_type_choices, default=0)
    username = models.CharField(max_length=64)
    password = models.CharField(max_length=64, blank=True, null=True)

    def __str__(self):
        return "%s:%s" % (self.username, self.password)

    class Meta:
        unique_together = ('auth_type', "username", "password")


class BindHost(models.Model):
    host = models.ForeignKey("Host")
    host_user = models.ForeignKey("HostUser")
    def __str__(self):
        return "%s@%s" % (self.host, self.host_user)

    class Meta:
        unique_together = ("host", "host_user")



