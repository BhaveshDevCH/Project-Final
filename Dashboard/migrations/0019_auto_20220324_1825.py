# Generated by Django 3.2.8 on 2022-03-24 12:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Dashboard', '0018_auto_20220324_1756'),
    ]

    operations = [
        migrations.AddField(
            model_name='observableobject',
            name='spec_version',
            field=models.IntegerField(default=2.1),
        ),
        migrations.AddField(
            model_name='stixobject',
            name='spec_version',
            field=models.IntegerField(default=2.1),
        ),
        migrations.AlterField(
            model_name='identity',
            name='identity_class',
            field=models.CharField(choices=[('class', 'class'), ('group', 'group'), ('unknown', 'unknown'), ('individual', 'individual'), ('organization', 'organization')], max_length=250),
        ),
        migrations.AlterField(
            model_name='markingdefinition',
            name='definition_type',
            field=models.CharField(choices=[('statement', 'statement'), ('tlp', 'tlp')], max_length=250),
        ),
    ]
