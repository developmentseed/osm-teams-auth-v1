import React, { Component } from 'react'
import Button from '../components/button'
import Router from 'next/router'
import join from 'url-join'
import getConfig from 'next/config'
import theme from '../styles/theme'

const { publicRuntimeConfig } = getConfig()
const URL = publicRuntimeConfig.APP_URL

const title = String.raw`
   ____  _____ __  ___   _______________    __  ________
  / __ \/ ___//  |/  /  /_  __/ ____/   |  /  |/  / ___/
 / / / /\__ \/ /|_/ /    / / / __/ / /| | / /|_/ /\__ \
/ /_/ /___/ / /  / /    / / / /___/ ___ |/ /  / /___/ /
\____//____/_/  /_/    /_/ /_____/_/  |_/_/  /_//____/
`

class Home extends Component {
  static async getInitialProps ({ query }) {
    if (query.user) {
      return {
        user: {
          username: query.user
        }
      }
    }
  }

  render () {
    return (
      <main>
        <section className='inner page welcome'>
          <div className='card'>
            <h1 className='welcome__intro'>
              <pre>{title}</pre>
            </h1>
            <p>
              Create teams of {publicRuntimeConfig.OSM_NAME} users and import
              them into your apps. Making maps better, together. Enable teams in
              OpenStreetMap applications, or build your team here. It’s not safe
              to map alone.
            </p>
            {this.props.user.username ? (
              <div className='welcome__user'>
                <h2>Welcome, {this.props.user.username}!</h2>
                <ul className='welcome__user--actions'>
                  <li>
                    <a href='https://mapping.team/'>Manage Your Teams</a>
                  </li>
                  <li>
                    <a href='https://mapping.team/developers'>
                      Teams Developer Docs
                    </a>
                  </li>
                  <li>
                    <a
                      href={join(publicRuntimeConfig.APP_URL, '/clients')}
                      className=''
                    >
                      Connected Apps
                    </a>
                  </li>
                </ul>
                <Button
                  variant='danger'
                  onClick={() => {
                    window.sessionStorage.clear()
                    Router.push('/logout')
                  }}
                >
                  Logout
                </Button>
              </div>
            ) : (
              <Button href='/login'>Sign in →</Button>
            )}
          </div>
          <div className='map-bg' />
        </section>
        <style jsx>
          {`
            main {
              background: ${theme.colors.primaryDark};
              background-image: radial-gradient(white 5%, transparent 0);
              background-repeat: repeat;
              background-size: 30px 30px;
              font-family: ${theme.typography.headingFontFamily};
              text-transform: uppercase;
              position: relative;
              z-index: 1;
              grid-area: main;
              overflow: inherit;
              padding-bottom: 2rem;
            }
            main:after {
              content: '';
              position: absolute;
              top: 0;
              left: 0;
              right: 0;
              bottom: 0;
              height: 100%;
              width: 100%;
              opacity: 0.8;
              z-index: -1;
              background: url(${join(URL, '/static/grid-map.svg')});
              background-size: contain;
              background-repeat: no-repeat;
              background-position: center 75%;
            }

            .card,
            .card h1,
            .card h2,
            .card a {
              color: white;
            }

            .welcome .card {
              display: flex;
              flex-flow: column wrap;
              text-align: left;
              align-items: flex-end;
              max-width: 48rem;
              padding: 2rem;
              background: rgba(25,51,130, 0.9);
              border: 4px solid white;
              position: relative;
              box-shadow: 12px 12px 0 ${
      theme.colors.primaryDark
      }, 12px 12px 0 3px white;
            }

            .welcome__intro {
              font-size: .8rem;
              font-size: 2.75vw;
              margin-bottom: 2rem;
              width: 100%;
            }

            pre {
              max-width: 100%;
              line-height: 1;
              margin: 0;
              font-family: ${theme.typography.headingFontFamily};
            }

            pre,
            .welcome__intro + p,
            .welcome__user h2,
            .welcome__user--actions {
              animation: VHS 2s cubic-bezier(0,1.21,.84,1.04) 5 alternate;
              transition: text-shadow 0.5s ease;
            }

            pre:hover,
            .welcome__intro + p:hover,
            .welcome__user h2:hover,
            .welcome__user--actions:hover {
              text-shadow: -1px 0 blue,
                            1px 0 red;
            }

            @keyframes VHS {
              0%{
                text-shadow: -4px -1px 1px blue,
                              4px 1px 1px red;
              }
              10%{
                text-shadow: -2px 0 blue,
                              2px 0 red;
              }
              100%{
                text-shadow: -1px 0 red,
                              1px 0 blue;
              }
            }

            .welcome__intro + p {
              padding-bottom: 2rem;
            }

            .welcome__user {
              align-self: flex-start;
              width: 100%;
              border: 2px dashed white;
              padding: 2rem;
            }

            .welcome__user--actions {
              list-style: none;
              display: flex;
              flex-direction: column;
              margin-block-start: 0;
              margin-block-end: 0;
              padding-inline-start: 0;
              padding: ${theme.layout.globalSpacing} 0;
            }

            .welcome__user--actions li {
              padding-bottom: calc(${theme.layout.globalSpacing} / 2);
            }

            .welcome__user--actions li:before {
              content: '--';
              line-height: 1;
              margin-right: 10px;
              color: ${theme.colors.secondaryColor};
            }

            .welcome__user--actions a:hover {
              text-decoration: underline;
            }

            @media screen and (min-width: ${theme.mediaRanges.small}) {
              .welcome .card {
                margin-top: 4rem;
                margin-left: 2rem;
                font-size: 1.125rem;
              }
              .welcome__intro {
                font-size: 1rem;
              }
            }

            @media screen and (min-width: ${theme.mediaRanges.large}) {
                main:after {
                  background-position: center bottom;
                }
                .inner.page.welcome{
                  margin-left: 0;
                }
                .welcome__intro {
                  font-size: 1.25rem;
                }
                .welcome .card {
                  margin-left: 4rem;
                }
              }
            }
          `}
        </style>
      </main>
    )
  }
}

export default Home
