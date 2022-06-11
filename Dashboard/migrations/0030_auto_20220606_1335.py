# Generated by Django 3.2.8 on 2022-06-06 08:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Dashboard', '0029_auto_20220502_1506'),
    ]

    operations = [
        migrations.AlterField(
            model_name='fileupload',
            name='file_hash',
            field=models.CharField(max_length=256),
        ),
        migrations.AlterField(
            model_name='fileupload',
            name='file_name',
            field=models.CharField(max_length=256),
        ),
        migrations.AlterField(
            model_name='identity',
            name='identity_class',
            field=models.CharField(choices=[('class', 'class'), ('individual', 'individual'), ('group', 'group'), ('unknown', 'unknown'), ('organization', 'organization')], max_length=250),
        ),
    ]
