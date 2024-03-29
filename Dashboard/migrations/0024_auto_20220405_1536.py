# Generated by Django 3.2.8 on 2022-04-05 10:06

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Dashboard', '0023_auto_20220324_1936'),
    ]

    operations = [
        migrations.AddField(
            model_name='profile',
            name='api_calls',
            field=models.IntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='identity',
            name='identity_class',
            field=models.CharField(choices=[('class', 'class'), ('individual', 'individual'), ('group', 'group'), ('organization', 'organization'), ('unknown', 'unknown')], max_length=250),
        ),
        migrations.AlterField(
            model_name='markingdefinition',
            name='definition_type',
            field=models.CharField(choices=[('statement', 'statement'), ('tlp', 'tlp')], max_length=250),
        ),
    ]
