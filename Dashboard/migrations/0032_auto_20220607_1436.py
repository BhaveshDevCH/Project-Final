# Generated by Django 3.2.8 on 2022-06-07 09:06

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Dashboard', '0031_auto_20220607_1429'),
    ]

    operations = [
        migrations.AlterField(
            model_name='identity',
            name='identity_class',
            field=models.CharField(choices=[('group', 'group'), ('class', 'class'), ('unknown', 'unknown'), ('organization', 'organization'), ('individual', 'individual')], max_length=250),
        ),
        migrations.AlterField(
            model_name='sites',
            name='created',
            field=models.DateTimeField(max_length=50),
        ),
    ]