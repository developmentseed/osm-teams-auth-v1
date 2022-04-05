import React, { Component } from 'react'
import theme from '../styles/theme'
import CreatableSelect from 'react-select/creatable'
import * as Yup from 'yup'
import Router from 'next/router'
import descriptionPopup from './description-popup'
import { Formik, Field, useField, Form, ErrorMessage } from 'formik'
import { getOrgMemberAttributes, getTeamMemberAttributes, getMyProfile, setMyProfile } from '../lib/profiles-api'
import { getTeam } from '../lib/teams-api'
import Button from '../components/button'
import { propOr } from 'ramda'

function GenderSelectField (props) {
  const [field, meta, { setValue, setTouched }] = useField(props.name)

  const onChange = function (option) {
    if (option) {
      return setValue(option.value)
    } else {
      return setValue(null)
    }
  }

  const options = [
    { value: 'non-binary', label: 'Non-Binary' },
    { value: 'female', label: 'Female' },
    { value: 'male', label: 'Male' },
    { value: 'undisclosed', label: 'I prefer not to say' }
  ]

  function findOrCreate (fieldValue) {
    let found = options.find((option) => option.value === field.value)
    if (!fieldValue) {
      return null
    }
    if (!found) {
      return { value: fieldValue, label: fieldValue }
    }
    return found
  }

  const styles = {
    control: (provided) => ({
      ...provided,
      minWidth: '220px',
      width: '220px',
      border: `2px solid ${theme.colors.primaryColor}`
    }),
    option: (provided) => ({
      ...provided,
      minWidth: '220px',
      width: '220px'
    })

  }

  return <div>
    <CreatableSelect
      styles={styles}
      isClearable
      formatCreateLabel={(inputValue) => `Write in ${inputValue}`}
      placeholder='Write or select'
      defaultValue={findOrCreate(field.value)}
      options={options}
      onChange={onChange}
      onBlur={setTouched}
    />
    {meta.touched && meta.error ? (
      <div className='form--error'>
        <ErrorMessage name={props.name} />
      </div>
    ) : null}
  </div>
}

export default class ProfileForm extends Component {
  static async getInitialProps ({ query }) {
    if (query) {
      return {
        id: query.id
      }
    }
  }

  constructor (props) {
    super(props)
    this.state = {
      memberAttributes: [],
      orgAttributes: [],
      profileValues: {},
      loading: true,
      error: undefined
    }
  }

  async componentDidMount () {
    this.getProfileForm()
  }

  async getProfileForm () {
    const { id } = this.props
    try {
      let memberAttributes = []
      let orgAttributes = []
      const returnUrl = `/teams/${this.props.id}`
      const team = await getTeam(id)
      if (team.org) {
        orgAttributes = await getOrgMemberAttributes(team.org.organization_id)
      }
      memberAttributes = await getTeamMemberAttributes(id)
      let profileValues = (await getMyProfile()).tags
      this.setState({
        id,
        returnUrl,
        memberAttributes,
        orgAttributes,
        profileValues,
        loading: false
      })
    } catch (e) {
      console.error(e)
      this.setState({
        error: e,
        loading: false
      })
    }
  }

  render () {
    let { memberAttributes, orgAttributes, profileValues, returnUrl, loading } = this.state

    if (loading) {
      return <div>Loading...</div>
    }

    const allAttributes = memberAttributes.concat(orgAttributes)
    let initialValues = {}

    let schema = {}

    allAttributes.forEach(attr => {
      // Set initial value from profileValues or to empty string
      initialValues[attr.id] = propOr('', attr.id, profileValues)

      // Set form validator
      switch (attr.key_type) {
        case 'email': {
          schema[attr.id] = Yup.string().email('Invalid email')
          break
        }
        case 'number': {
          schema[attr.id] = Yup.number().typeError('Invalid number')
          break
        }
        case 'url': {
          schema[attr.id] = Yup.string().url('Invalid URL')
          break
        }
        case 'date': {
          schema[attr.id] = Yup.date('Invalid date')
          break
        }
        case 'tel': {
          const phoneRegex = /^((\\+[1-9]{1,4}[ \\-]*)|(\\([0-9]{2,3}\\)[ \\-]*)|([0-9]{2,4})[ \\-]*)*?[0-9]{3,4}?[ \\-]*[0-9]{3,4}?$/
          schema[attr.id] = Yup.string().matches(phoneRegex, 'Invalid phone number')
          break
        }
        case 'color': {
          const hexRegex = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i
          schema[attr.id] = Yup.string().matches(hexRegex, 'Invalid color code')
          break
        }
        default: {
          if (attr.required) {
            schema[attr.id] = Yup.string().required('This is a required field').nullable()
          } else {
            schema[attr.id] = Yup.string().nullable()
          }
        }
      }
    })
    const yupSchema = Yup.object().shape(schema)

    return (
      <article className='inner page'>
        <h1>Add Your Profile</h1>
        <Formik
          enableReinitialize
          validateOnBlur
          validationSchema={yupSchema}
          initialValues={initialValues}
          onSubmit={async (values, actions) => {
            const data = Object.keys(values).map(key => ({
              'key_id': key,
              'value': values[key]
            }))
            actions.setSubmitting(true)
            try {
              await setMyProfile(data)
              actions.setSubmitting(false)
              Router.push(returnUrl)
            } catch (e) {
              console.error(e)
              actions.setSubmitting(false)
              actions.setStatus(e.message)
            }
          }}
          render={({ errors, status, isSubmitting, values }) => {
            const addProfileText = `Submit ${isSubmitting ? ' 🕙' : ''}`
            return (
              <Form>
                {orgAttributes.length > 0
                  ? <>
                    <h2>Org Profile</h2>
                    {orgAttributes.map(attribute => {
                      return <div className='form-control form-control__vertical'>
                        <label>{attribute.name}
                          {attribute.required ? <span className='form--required'>*</span> : ''}
                          {attribute.description ? descriptionPopup(attribute.description) : ''}
                        </label>
                        { attribute.key_type === 'gender'
                        ? <label>Type in or select your gender from the drop-down.</label>
                        : null
                        }
                        { attribute.key_type === 'gender'
                          ?
                          <GenderSelectField name={attribute.id} />
                          : <>
                            <Field
                              type={attribute.key_type}
                              name={attribute.id}
                              required={attribute.required}
                            />
                            <div className='form--error'>
                              <ErrorMessage name={attribute.id} />
                            </div>
                          </>
                        }
                      </div>
                    })}
                  </>
                  : ''
                }
                <h2>Team Profile</h2>
                { memberAttributes.length > 0 ? memberAttributes.map(attribute => {
                  return <div className='form-control form-control__vertical'>
                    <label>{attribute.name}
                      {attribute.required ? <span className='form--required'>*</span> : ''}
                      {attribute.description ? descriptionPopup(attribute.description) : ''}
                    </label>
                    {attribute.key_type === 'gender'
                      ? <label>Type in or select your gender from the drop-down.</label>
                      : null
                    }
                    {attribute.key_type === 'gender'
                      ? <GenderSelectField name={attribute.id} />
                      : <>
                        <Field
                          type={attribute.key_type}
                          name={attribute.id}
                          required={attribute.required}
                        />
                        <div className='form--error'>
                          <ErrorMessage name={attribute.id} />
                        </div>
                      </>
                    }
                  </div>
                })
                  : 'No profile form to fill yet'
                }
                {status && status.msg && <div>{status.msg}</div>}
                <div style={{ marginTop: '1rem' }}className='form-control form-control__vertical'>
                  <Button type='submit' variant='submit' disabled={isSubmitting}>
                    {addProfileText}
                  </Button>
                </div>
              </Form>
            )
          }}
        />
      </article>
    )
  }
}
