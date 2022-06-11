# Generated by Django 3.2.8 on 2022-05-02 09:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Dashboard', '0028_auto_20220502_1502'),
    ]

    operations = [
        migrations.AlterField(
            model_name='identity',
            name='identity_class',
            field=models.CharField(choices=[('class', 'class'), ('group', 'group'), ('individual', 'individual'), ('unknown', 'unknown'), ('organization', 'organization')], max_length=250),
        ),
        migrations.AlterField(
            model_name='plandetails',
            name='plan',
            field=models.CharField(choices=[('Free', 'Free'), ('Gold', 'Gold'), ('Plantinum', 'Plantinum')], default='Free', max_length=20),
        ),
        migrations.AlterField(
            model_name='plandetails',
            name='plan_exp',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='plandetails',
            name='plan_init',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
