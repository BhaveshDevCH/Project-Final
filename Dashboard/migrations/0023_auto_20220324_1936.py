# Generated by Django 3.2.8 on 2022-03-24 14:06

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Dashboard', '0022_auto_20220324_1930'),
    ]

    operations = [
        migrations.RenameField(
            model_name='bundleobject',
            old_name='objects',
            new_name='objects_list',
        ),
        migrations.AlterField(
            model_name='identity',
            name='identity_class',
            field=models.CharField(choices=[('class', 'class'), ('group', 'group'), ('unknown', 'unknown'), ('organization', 'organization'), ('individual', 'individual')], max_length=250),
        ),
    ]