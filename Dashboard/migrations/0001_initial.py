# Generated by Django 3.2.8 on 2022-03-24 07:42

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AttackPatternAlias',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=250, unique=True)),
            ],
            options={
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='Bins',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('url', models.CharField(max_length=50)),
                ('bin_name', models.CharField(max_length=50)),
                ('index_on', models.DateField()),
                ('Last_seen', models.CharField(max_length=50)),
                ('keywords', models.CharField(max_length=50)),
                ('screenshot', models.CharField(default='null', max_length=50, null=True)),
                ('content', models.CharField(max_length=50)),
                ('visible', models.IntegerField()),
                ('reported', models.IntegerField()),
                ('reported_by', models.CharField(max_length=50, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='CampaignAlias',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=250, unique=True)),
            ],
            options={
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='Category',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=50)),
                ('category', models.CharField(choices=[('Dating', 'Dating'), ('Forums', 'Forums'), ('Gaming', 'Gaming'), ('International', 'International'), ('SocialMedia', 'SocialMedia')], max_length=25)),
                ('url', models.URLField()),
                ('logo', models.ImageField(upload_to='Logo/')),
            ],
        ),
        migrations.CreateModel(
            name='ExternalRefrence',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('source_name', models.CharField(blank=True, max_length=100, null=True)),
                ('description', models.CharField(blank=True, max_length=500, null=True)),
                ('url', models.CharField(blank=True, max_length=250, null=True)),
                ('hashes_md5', models.CharField(blank=True, max_length=250, null=True)),
                ('hashes_sha1', models.CharField(blank=True, max_length=250, null=True)),
                ('hashes_sha256', models.CharField(blank=True, max_length=250, null=True)),
                ('external_id', models.CharField(blank=True, max_length=100, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='IdentityLabel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.CharField(max_length=250, unique=True)),
                ('alias', models.CharField(blank=True, max_length=250, null=True)),
            ],
            options={
                'ordering': ['value'],
            },
        ),
        migrations.CreateModel(
            name='IndicatorLabel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.CharField(max_length=250, unique=True)),
            ],
            options={
                'ordering': ['value'],
            },
        ),
        migrations.CreateModel(
            name='IndustrySector',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.CharField(max_length=250, unique=True)),
                ('description', models.TextField(blank=True, null=True)),
            ],
            options={
                'ordering': ['value'],
            },
        ),
        migrations.CreateModel(
            name='IntrusionSetAlias',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=250, unique=True)),
            ],
            options={
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='MalwareLabel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.CharField(max_length=250, unique=True)),
            ],
            options={
                'ordering': ['value'],
            },
        ),
        migrations.CreateModel(
            name='ObservableObjectType',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=250, unique=True)),
                ('model_name', models.CharField(blank=True, max_length=250, null=True, unique=True)),
            ],
            options={
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='RelationshipType',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=250, unique=True)),
            ],
            options={
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='ReportLabel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.CharField(max_length=250, unique=True)),
            ],
            options={
                'ordering': ['value'],
            },
        ),
        migrations.CreateModel(
            name='Sites',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('url', models.CharField(max_length=50)),
                ('ip', models.CharField(default='null', max_length=50, null=True)),
                ('date_added', models.DateField(max_length=50)),
                ('is_up', models.CharField(default='True', max_length=50)),
                ('last_seen', models.DateField(max_length=50)),
                ('keywords', models.CharField(max_length=50)),
                ('next_check_schedule', models.DateTimeField(max_length=50)),
                ('ssh_fingerprint', models.CharField(max_length=50)),
                ('language', models.CharField(max_length=50)),
                ('screenshot', models.ImageField(upload_to='screenshots/')),
                ('content', models.CharField(max_length=50)),
                ('visible', models.IntegerField(default='')),
                ('reported', models.CharField(default='null', max_length=50, null=True)),
                ('reported_by', models.IntegerField(default='null', null=True)),
                ('added_by', models.CharField(default='Kaptaan', max_length=50)),
                ('description', models.CharField(max_length=50)),
            ],
        ),
        migrations.CreateModel(
            name='STIXObject',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(null=True)),
                ('modified', models.DateTimeField(null=True)),
                ('confidence', models.PositiveSmallIntegerField(blank=True, null=True)),
                ('lang', models.CharField(blank=True, max_length=50, null=True)),
            ],
            options={
                'ordering': ['object_type', 'object_id'],
            },
        ),
        migrations.CreateModel(
            name='STIXObjectID',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('object_id', models.CharField(max_length=250, unique=True)),
            ],
            options={
                'ordering': ['object_id'],
            },
        ),
        migrations.CreateModel(
            name='STIXObjectType',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=250, unique=True)),
                ('model_name', models.CharField(blank=True, max_length=250, null=True)),
            ],
            options={
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='ThreatActorAlias',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=250, unique=True)),
                ('description', models.TextField(blank=True, null=True)),
            ],
            options={
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='ThreatActorLabel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.CharField(max_length=250, unique=True)),
            ],
            options={
                'ordering': ['value'],
            },
        ),
        migrations.CreateModel(
            name='ToolLabel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.CharField(max_length=250, unique=True)),
            ],
            options={
                'ordering': ['value'],
            },
        ),
        migrations.CreateModel(
            name='CourseOfAction',
            fields=[
                ('stixobject_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='Dashboard.stixobject')),
                ('name', models.CharField(max_length=250, unique=True)),
                ('description', models.TextField(blank=True, null=True)),
            ],
            options={
                'ordering': ['name'],
            },
            bases=('Dashboard.stixobject',),
        ),
        migrations.CreateModel(
            name='Identity',
            fields=[
                ('stixobject_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='Dashboard.stixobject')),
                ('name', models.CharField(max_length=250, unique=True)),
                ('identity_class', models.CharField(choices=[('organization', 'organization'), ('unknown', 'unknown'), ('class', 'class'), ('individual', 'individual'), ('group', 'group')], max_length=250)),
                ('description', models.TextField(blank=True, null=True)),
                ('labels', models.ManyToManyField(blank=True, to='Dashboard.IdentityLabel')),
                ('sectors', models.ManyToManyField(blank=True, to='Dashboard.IndustrySector')),
            ],
            options={
                'ordering': ['name'],
            },
            bases=('Dashboard.stixobject',),
        ),
        migrations.CreateModel(
            name='ObservedData',
            fields=[
                ('stixobject_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='Dashboard.stixobject')),
                ('first_observed', models.DateTimeField()),
                ('last_observed', models.DateTimeField()),
                ('number_observed', models.PositiveSmallIntegerField(default=1)),
            ],
            bases=('Dashboard.stixobject',),
        ),
        migrations.CreateModel(
            name='Vulnerability',
            fields=[
                ('stixobject_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='Dashboard.stixobject')),
                ('name', models.CharField(max_length=250, unique=True)),
                ('description', models.TextField(blank=True, null=True)),
            ],
            options={
                'ordering': ['name'],
            },
            bases=('Dashboard.stixobject',),
        ),
        migrations.CreateModel(
            name='TaxiiCollection',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('collection_id', models.CharField(blank=True, max_length=250, null=True, unique=True)),
                ('title', models.CharField(max_length=250, unique=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('can_read', models.BooleanField(default=True)),
                ('can_write', models.BooleanField(default=False)),
                ('stix_objects', models.ManyToManyField(to='Dashboard.STIXObject')),
            ],
        ),
        migrations.AddField(
            model_name='stixobject',
            name='created_by_ref',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='created_by_ref', to='Dashboard.stixobjectid'),
        ),
        migrations.AddField(
            model_name='stixobject',
            name='external_references',
            field=models.ManyToManyField(blank=True, null=True, to='Dashboard.ExternalRefrence'),
        ),
        migrations.AddField(
            model_name='stixobject',
            name='object_id',
            field=models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='Dashboard.stixobjectid'),
        ),
        migrations.AddField(
            model_name='stixobject',
            name='object_type',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='Dashboard.stixobjecttype'),
        ),
        migrations.CreateModel(
            name='Profile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('first_name', models.CharField(default='', max_length=15)),
                ('last_name', models.CharField(default='', max_length=15)),
                ('email', models.EmailField(default='', max_length=100)),
                ('website_link', models.URLField(null=True)),
                ('organization', models.CharField(default='', max_length=50)),
                ('profile_img', models.ImageField(upload_to='profile/')),
                ('twitter', models.URLField()),
                ('facebook', models.URLField()),
                ('linkedin', models.URLField()),
                ('phone', models.CharField(max_length=12)),
                ('country', models.CharField(choices=[('India', 'India'), ('Nepal', 'Nepal')], max_length=30)),
                ('credits', models.IntegerField(default=0)),
                ('max_credits', models.IntegerField(default=0)),
                ('max_entities', models.IntegerField(default=0)),
                ('plan', models.CharField(choices=[('Gold', 'Gold'), ('Plantinum', 'Plantinum'), ('Silver', 'Silver')], default='', max_length=20)),
                ('plan_init', models.DateTimeField(blank=True, default=django.utils.timezone.now)),
                ('plan_exp', models.DateTimeField(blank=True, default=django.utils.timezone.now)),
                ('username', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='user_profile', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='ObservableObject',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('object_id', models.CharField(blank=True, max_length=250, null=True, unique=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('type', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Dashboard.observableobjecttype')),
            ],
            options={
                'ordering': ['type'],
            },
        ),
        migrations.CreateModel(
            name='Monitored_Identity',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('identity', models.URLField()),
                ('status', models.BooleanField(default=True, null=True)),
                ('init_date', models.DateTimeField(auto_now_add=True, null=True)),
                ('inactive_date', models.DateTimeField(null=True)),
                ('username', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Dashboard.profile')),
            ],
        ),
        migrations.CreateModel(
            name='KillChainPhase',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('kill_chain_name', models.CharField(max_length=250)),
                ('phase_name', models.CharField(max_length=250)),
                ('seq', models.SmallIntegerField(default=1)),
            ],
            options={
                'ordering': ['seq'],
                'unique_together': {('kill_chain_name', 'phase_name')},
            },
        ),
        migrations.CreateModel(
            name='IndicatorPattern',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('pattern', models.TextField()),
                ('observable', models.ManyToManyField(to='Dashboard.ObservableObject')),
            ],
        ),
        migrations.CreateModel(
            name='Indexer',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('url', models.CharField(default='null', max_length=50, null=True)),
                ('email', models.CharField(default='null', max_length=50, null=True)),
                ('type', models.CharField(default='null', max_length=50, null=True)),
                ('scheduled_scanned', models.TimeField(null=True)),
                ('last_scanned', models.TimeField(null=True)),
                ('current_status', models.CharField(default='Pending', max_length=50, null=True)),
                ('username', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Dashboard.profile')),
            ],
        ),
        migrations.CreateModel(
            name='URLObject',
            fields=[
                ('observableobject_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='Dashboard.observableobject')),
                ('value', models.CharField(max_length=10000, unique=True)),
                ('resolves_to_refs_u', models.ManyToManyField(blank=True, related_name='url_refs', to='Dashboard.ObservableObject')),
            ],
            options={
                'ordering': ['value'],
            },
            bases=('Dashboard.observableobject',),
        ),
        migrations.CreateModel(
            name='Tool',
            fields=[
                ('stixobject_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='Dashboard.stixobject')),
                ('name', models.CharField(max_length=250, unique=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('kill_chain_phases', models.ManyToManyField(blank=True, to='Dashboard.KillChainPhase')),
                ('labels', models.ManyToManyField(blank=True, to='Dashboard.ToolLabel')),
            ],
            options={
                'ordering': ['name'],
            },
            bases=('Dashboard.stixobject',),
        ),
        migrations.CreateModel(
            name='ThreatActor',
            fields=[
                ('stixobject_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='Dashboard.stixobject')),
                ('name', models.CharField(max_length=250, unique=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('aliases', models.ManyToManyField(blank=True, to='Dashboard.ThreatActorAlias')),
                ('labels', models.ManyToManyField(blank=True, to='Dashboard.ThreatActorLabel')),
            ],
            options={
                'ordering': ['name'],
            },
            bases=('Dashboard.stixobject',),
        ),
        migrations.AlterUniqueTogether(
            name='stixobject',
            unique_together={('object_type', 'object_id')},
        ),
        migrations.CreateModel(
            name='Sighting',
            fields=[
                ('stixobject_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='Dashboard.stixobject')),
                ('first_seen', models.DateTimeField()),
                ('last_seen', models.DateTimeField(blank=True, null=True)),
                ('observed_data_refs', models.ManyToManyField(related_name='observed_data_refs', to='Dashboard.ObservedData')),
                ('sighting_of_ref', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sighting_of_ref', to='Dashboard.stixobjectid')),
                ('where_sighted_refs', models.ManyToManyField(related_name='where_sighted_ref', to='Dashboard.Identity')),
            ],
            bases=('Dashboard.stixobject',),
        ),
        migrations.CreateModel(
            name='Report',
            fields=[
                ('stixobject_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='Dashboard.stixobject')),
                ('name', models.CharField(max_length=250, unique=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('published', models.DateTimeField(blank=True, null=True)),
                ('labels', models.ManyToManyField(to='Dashboard.ReportLabel')),
                ('object_refs', models.ManyToManyField(blank=True, to='Dashboard.STIXObjectID')),
            ],
            options={
                'ordering': ['name'],
            },
            bases=('Dashboard.stixobject',),
        ),
        migrations.CreateModel(
            name='Relationship',
            fields=[
                ('stixobject_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='Dashboard.stixobject')),
                ('description', models.TextField(blank=True, null=True)),
                ('relationship_type', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Dashboard.relationshiptype')),
                ('source_ref', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='source_ref', to='Dashboard.stixobjectid')),
                ('target_ref', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='target_ref', to='Dashboard.stixobjectid')),
            ],
            bases=('Dashboard.stixobject',),
        ),
        migrations.AddField(
            model_name='observeddata',
            name='observable_objects',
            field=models.ManyToManyField(to='Dashboard.ObservableObject'),
        ),
        migrations.CreateModel(
            name='MarkingDefinition',
            fields=[
                ('stixobject_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='Dashboard.stixobject')),
                ('definition_type', models.CharField(choices=[('statement', 'statement'), ('tlp', 'tlp')], max_length=250)),
                ('definition', models.CharField(max_length=250)),
            ],
            options={
                'ordering': ['definition_type', 'definition'],
                'unique_together': {('definition_type', 'definition')},
            },
            bases=('Dashboard.stixobject',),
        ),
        migrations.CreateModel(
            name='Malware',
            fields=[
                ('stixobject_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='Dashboard.stixobject')),
                ('name', models.CharField(max_length=250, unique=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('kill_chain_phases', models.ManyToManyField(blank=True, to='Dashboard.KillChainPhase')),
                ('labels', models.ManyToManyField(to='Dashboard.MalwareLabel')),
            ],
            options={
                'ordering': ['name'],
            },
            bases=('Dashboard.stixobject',),
        ),
        migrations.CreateModel(
            name='IPv4AddressObject',
            fields=[
                ('observableobject_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='Dashboard.observableobject')),
                ('value', models.CharField(max_length=15, unique=True)),
                ('resolves_to_refs', models.ManyToManyField(blank=True, related_name='ip_refs', to='Dashboard.ObservableObject')),
            ],
            options={
                'ordering': ['value'],
            },
            bases=('Dashboard.observableobject',),
        ),
        migrations.CreateModel(
            name='IntrusionSet',
            fields=[
                ('stixobject_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='Dashboard.stixobject')),
                ('name', models.CharField(max_length=250, unique=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('first_seen', models.DateTimeField(blank=True, null=True)),
                ('last_seen', models.DateTimeField(blank=True, null=True)),
                ('aliases', models.ManyToManyField(blank=True, to='Dashboard.IntrusionSetAlias')),
            ],
            options={
                'ordering': ['name'],
            },
            bases=('Dashboard.stixobject',),
        ),
        migrations.CreateModel(
            name='Indicator',
            fields=[
                ('stixobject_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='Dashboard.stixobject')),
                ('name', models.CharField(max_length=250, unique=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('valid_from', models.DateTimeField(blank=True, null=True)),
                ('valid_until', models.DateTimeField(blank=True, null=True)),
                ('kill_chain_phases', models.ManyToManyField(blank=True, to='Dashboard.KillChainPhase')),
                ('labels', models.ManyToManyField(to='Dashboard.IndicatorLabel')),
                ('pattern', models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='Dashboard.indicatorpattern')),
            ],
            bases=('Dashboard.stixobject',),
        ),
        migrations.CreateModel(
            name='FileObject',
            fields=[
                ('observableobject_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='Dashboard.observableobject')),
                ('name', models.CharField(max_length=10000, unique=True)),
                ('hashes_md5', models.CharField(blank=True, max_length=250, null=True)),
                ('hashes_sha1', models.CharField(blank=True, max_length=250, null=True)),
                ('hashes_sha256', models.CharField(blank=True, max_length=250, null=True)),
                ('contains_refs', models.ManyToManyField(blank=True, related_name='contains_refs', to='Dashboard.ObservableObject')),
            ],
            options={
                'ordering': ['name'],
            },
            bases=('Dashboard.observableobject',),
        ),
        migrations.CreateModel(
            name='DomainNameObject',
            fields=[
                ('observableobject_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='Dashboard.observableobject')),
                ('value', models.CharField(max_length=10000, unique=True)),
                ('resolves_to_refs', models.ManyToManyField(blank=True, related_name='resolves_to_refs', to='Dashboard.ObservableObject')),
            ],
            options={
                'ordering': ['value'],
            },
            bases=('Dashboard.observableobject',),
        ),
        migrations.CreateModel(
            name='DefinedRelationship',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('source', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='source', to='Dashboard.stixobjecttype')),
                ('target', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='target', to='Dashboard.stixobjecttype')),
                ('type', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Dashboard.relationshiptype')),
            ],
            options={
                'ordering': ['source', 'type', 'target'],
                'unique_together': {('source', 'type', 'target')},
            },
        ),
        migrations.CreateModel(
            name='Campaign',
            fields=[
                ('stixobject_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='Dashboard.stixobject')),
                ('name', models.CharField(max_length=250, unique=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('first_seen', models.DateTimeField(blank=True, null=True)),
                ('last_seen', models.DateTimeField(blank=True, null=True)),
                ('aliases', models.ManyToManyField(blank=True, to='Dashboard.CampaignAlias')),
            ],
            options={
                'ordering': ['name'],
            },
            bases=('Dashboard.stixobject',),
        ),
        migrations.CreateModel(
            name='AttackPattern',
            fields=[
                ('stixobject_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='Dashboard.stixobject')),
                ('name', models.CharField(max_length=250, unique=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('aliases', models.ManyToManyField(blank=True, to='Dashboard.AttackPatternAlias')),
                ('kill_chain_phases', models.ManyToManyField(blank=True, to='Dashboard.KillChainPhase')),
            ],
            options={
                'ordering': ['name'],
            },
            bases=('Dashboard.stixobject',),
        ),
    ]
