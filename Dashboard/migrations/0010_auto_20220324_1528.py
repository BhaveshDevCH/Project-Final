# Generated by Django 3.2.8 on 2022-03-24 09:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Dashboard', '0009_auto_20220324_1516'),
    ]

    operations = [
        migrations.CreateModel(
            name='ToolTypes',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type', models.CharField(max_length=250, unique=True)),
            ],
        ),
        migrations.RenameModel(
            old_name='ToolLabel',
            new_name='ToolAlias',
        ),
        migrations.AlterModelOptions(
            name='toolalias',
            options={},
        ),
        migrations.RenameField(
            model_name='toolalias',
            old_name='value',
            new_name='name',
        ),
        migrations.RemoveField(
            model_name='tool',
            name='labels',
        ),
        migrations.AddField(
            model_name='tool',
            name='aliases',
            field=models.ManyToManyField(blank=True, to='Dashboard.ToolAlias'),
        ),
        migrations.AlterField(
            model_name='identity',
            name='identity_class',
            field=models.CharField(choices=[('individual', 'individual'), ('group', 'group'), ('class', 'class'), ('organization', 'organization'), ('unknown', 'unknown')], max_length=250),
        ),
        migrations.AddField(
            model_name='tool',
            name='tool_types',
            field=models.ManyToManyField(blank=True, to='Dashboard.ToolTypes'),
        ),
    ]
