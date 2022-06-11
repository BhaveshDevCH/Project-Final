# Generated by Django 3.2.8 on 2022-03-24 11:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Dashboard', '0012_auto_20220324_1639'),
    ]

    operations = [
        migrations.AlterField(
            model_name='identity',
            name='identity_class',
            field=models.CharField(choices=[('unknown', 'unknown'), ('organization', 'organization'), ('individual', 'individual'), ('class', 'class'), ('group', 'group')], max_length=250),
        ),
        migrations.AlterField(
            model_name='sighting',
            name='first_seen',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]