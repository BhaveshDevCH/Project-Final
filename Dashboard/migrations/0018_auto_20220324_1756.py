# Generated by Django 3.2.8 on 2022-03-24 12:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Dashboard', '0017_auto_20220324_1729'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='observableobject',
            name='description',
        ),
        migrations.RemoveField(
            model_name='urlobject',
            name='resolves_to_refs_u',
        ),
        migrations.AlterField(
            model_name='domainnameobject',
            name='resolves_to_refs',
            field=models.ManyToManyField(blank=True, related_name='resolve_to_refs_domain', to='Dashboard.ObservableObject'),
        ),
        migrations.AlterField(
            model_name='identity',
            name='identity_class',
            field=models.CharField(choices=[('unknown', 'unknown'), ('individual', 'individual'), ('organization', 'organization'), ('group', 'group'), ('class', 'class')], max_length=250),
        ),
        migrations.AlterField(
            model_name='ipv4addressobject',
            name='resolves_to_refs',
            field=models.ManyToManyField(blank=True, related_name='resolve_to_refs_ipv4', to='Dashboard.ObservableObject'),
        ),
    ]
