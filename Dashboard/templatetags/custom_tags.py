
from django import template
import datetime
register = template.Library()
@register.filter(name='split')
def split(value, key):
    """
        Returns the value turned into a list.
    """
    return value.split(key)


@register.filter(name='status')
def status(value):
    if value==True:
        return "Active"
    return "Inactive"

@register.filter(name='currentDate')
def currentDate(date):
    return date
    # currentDate=datetime.datetime.now()
    # currY=currentDate.year
    # currM=currentDate.month
    # currD=currentDate.day
    # date = datetime.datetime(date)
    # if date.year<currY:
    #     return str(currY-date.year)+" "+"year ago"
    # elif date.month<currM:
    #     return str(currM-date.month)+" "+"month ago"
    # return str(currD-date.day)+" "+"day ago"

@register.filter(name='countryFlag')
def countryFlag(value):
    value=value+".gif"
    return value.lower()